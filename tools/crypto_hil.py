#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicitly selected CTAP regression checks. Never resets, sets PIN, or flashes."""
import argparse
from contextlib import contextmanager
import getpass
import hashlib
from pathlib import Path
import secrets
from threading import Event, Timer

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import STATUS, list_descriptors, open_device


def choose(descriptors, vid, pid, serial):
    matches = [
        d for d in descriptors
        if d.vid == vid and d.pid == pid
        and (serial is None or d.serial_number == serial)
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one matching FIDO device, found {len(matches)}")
    return matches[0]


def keepalive(status):
    label = "waiting for button/touch" if status == STATUS.UPNEEDED else "processing"
    print(f"CTAPHID keepalive: {status.name} ({label})", flush=True)


@contextmanager
def deadline():
    event = Event()
    timer = Timer(120, event.set)
    timer.start()
    try:
        yield event
    finally:
        timer.cancel()


def authorization(ctap, client_hash, rp_id, use_pin, make=False):
    if not use_pin:
        return {}
    client_pin = ClientPin(ctap)
    permission = (ClientPin.PERMISSION.MAKE_CREDENTIAL if make
                  else ClientPin.PERMISSION.GET_ASSERTION)
    token = client_pin.get_pin_token(
        getpass.getpass("Existing authenticator PIN: "),
        permissions=permission, permissions_rpid=rp_id,
    )
    return {
        "pin_uv_param": client_pin.protocol.authenticate(token, client_hash),
        "pin_uv_protocol": client_pin.protocol.VERSION,
    }


def verify_assertion(state, response, client_hash, use_pin):
    auth = response.auth_data
    if auth.rp_id_hash != hashlib.sha256(state["rp_id"].encode()).digest():
        raise ValueError("Unexpected RP hash")
    if not auth.flags & 1:
        raise ValueError("User presence flag missing")
    if use_pin and not auth.flags & 4:
        raise ValueError("PIN user-verification flag missing")
    if response.credential is not None and response.credential["id"] != state["credential_id"]:
        raise ValueError("Unexpected credential ID")
    CoseKey.parse(state["public_key"]).verify(bytes(auth) + client_hash, response.signature)


def signature_label(state):
    return {-7: "ES256", -8: "Ed25519"}.get(
        state["public_key"][3], f"COSE {state['public_key'][3]}"
    )


def assert_credential(ctap, state, use_pin, discover=False):
    client_hash = secrets.token_bytes(32)
    allow_list = None if discover else [{"type": "public-key", "id": state["credential_id"]}]
    auth = authorization(ctap, client_hash, state["rp_id"], use_pin)
    print("Touch for getAssertion...", flush=True)
    with deadline() as event:
        responses = ctap.get_assertions(
            state["rp_id"], client_hash, allow_list,
            options={"up": True}, event=event, on_keepalive=keepalive, **auth,
        )
    matches = [
        r for r in responses
        if (r.credential is None and not discover)
        or (r.credential is not None and r.credential["id"] == state["credential_id"])
    ]
    if len(matches) != 1:
        raise ValueError("Saved credential not returned exactly once")
    verify_assertion(state, matches[0], client_hash, use_pin)
    print(f"getAssertion / {signature_label(state)} signature / RP / presence: PASS")
    if discover:
        print("Resident discovery: PASS")


def negatives(ctap, state, use_pin):
    for label, rp_id, credential_id in [
        ("Wrong RP", "wrong-" + state["rp_id"], state["credential_id"]),
        ("Tampered credential", state["rp_id"],
         state["credential_id"][:-1] + bytes([state["credential_id"][-1] ^ 1])),
    ]:
        client_hash = secrets.token_bytes(32)
        auth = authorization(ctap, client_hash, rp_id, use_pin)
        try:
            with deadline() as event:
                ctap.get_assertion(
                    rp_id, client_hash,
                    [{"type": "public-key", "id": credential_id}],
                    options={"up": True}, event=event, on_keepalive=keepalive, **auth,
                )
        except CtapError as error:
            if error.code != CtapError.ERR.NO_CREDENTIALS:
                raise
            print(f"{label} rejection: PASS (NO_CREDENTIALS)")
        else:
            raise ValueError(f"{label} unexpectedly accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["list", "info", "create", "assert"])
    parser.add_argument("--vid", type=lambda x: int(x, 0))
    parser.add_argument("--pid", type=lambda x: int(x, 0))
    parser.add_argument("--serial")
    parser.add_argument("--state", type=Path)
    parser.add_argument("--algorithm", choices=["es256", "ed25519"],
                        help="Credential algorithm for create (default: es256)")
    parser.add_argument("--pin", action="store_true", help="Use an already configured PIN")
    parser.add_argument("--resident", action="store_true", help="Create one resident test credential")
    parser.add_argument("--discover", action="store_true", help="Assert saved resident credential without allowList")
    parser.add_argument("--negative", action="store_true", help="Check wrong RP and tampered credential rejection")
    args = parser.parse_args()
    if args.operation != "list" and (args.vid is None or args.pid is None):
        parser.error("--vid and --pid are required to select the device")
    if args.operation in ("create", "assert") and args.state is None:
        parser.error("--state is required")
    if args.algorithm is not None and args.operation != "create":
        parser.error("--algorithm applies only to create")
    if args.resident and args.operation != "create":
        parser.error("--resident applies only to create")
    if args.discover and args.operation != "assert":
        parser.error("--discover applies only to assert")
    if args.operation == "create" and args.state.exists():
        parser.error("Refusing to overwrite an existing credential record")
    state = None
    if args.operation == "assert":
        state = cbor.decode(args.state.read_bytes())
        if args.discover and not state.get("resident", False):
            parser.error("--discover requires a saved resident test credential")
    descriptors = list(list_descriptors())
    if args.operation == "list":
        for d in descriptors:
            print(f"{d.vid:04x}:{d.pid:04x} serial={d.serial_number!r} product={d.product_name!r}")
        return
    descriptor = choose(descriptors, args.vid, args.pid, args.serial)
    device = open_device(descriptor.path)
    try:
        print(f"Selected {descriptor.vid:04x}:{descriptor.pid:04x} serial={descriptor.serial_number!r}")
        message = secrets.token_bytes(64)
        if device.ping(message) != message:
            raise ValueError("CTAPHID PING mismatch")
        print("USB FIDO enumeration / CTAPHID INIT and PING: PASS")
        ctap = Ctap2(device)
        info = ctap.info
        print("CTAP2 GetInfo: PASS")
        print("versions:", info.versions, "options:", info.options)
        print("AAGUID:", info.aaguid.hex(), "algorithms:", info.algorithms)
        if args.operation == "info":
            return
        if args.operation == "create":
            algorithm = {"es256": -7, "ed25519": -8}[args.algorithm or "es256"]
            rp_id = "crypto-hil-" + secrets.token_hex(8) + ".local"
            client_hash = secrets.token_bytes(32)
            auth = authorization(ctap, client_hash, rp_id, args.pin, make=True)
            print("Touch for makeCredential (creates one test credential)...", flush=True)
            with deadline() as event:
                att = ctap.make_credential(
                    client_hash, {"id": rp_id, "name": "OpenSK crypto HIL"},
                    {"id": secrets.token_bytes(16), "name": "crypto-hil"},
                    [{"type": "public-key", "alg": algorithm}],
                    options={"rk": args.resident}, event=event, on_keepalive=keepalive, **auth,
                )
            credential = att.auth_data.credential_data
            if credential is None or credential.public_key[3] != algorithm:
                raise ValueError("Credential algorithm does not match the request")
            state = {
                "rp_id": rp_id, "credential_id": credential.credential_id,
                "public_key": dict(credential.public_key), "resident": args.resident,
            }
            with args.state.open("xb") as output:
                output.write(cbor.encode(state))
            print(f"makeCredential {signature_label(state)}: PASS; public credential record saved to {args.state}")
        assert_credential(ctap, state, args.pin, args.discover)
        if args.negative:
            negatives(ctap, state, args.pin)
    finally:
        device.close()


if __name__ == "__main__":
    main()
