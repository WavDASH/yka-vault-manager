"""Explicit slot operations. Never change device credentials or reset PIV."""
from datetime import datetime, timedelta, timezone
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from yubikit.core.smartcard import ApduError
from yubikit.core import InvalidPinError, NotSupportedError
from yubikit.piv import KEY_TYPE, PIN_POLICY, TOUCH_POLICY, SLOT
from ykman.piv import generate_self_signed_certificate, get_pivman_data, get_pivman_protected_data
from . import piv
from .windows import VaultError


def _absent(session, read):
    try:
        read()
    except ApduError as error:
        if int(error.sw) == 0x6A82 or int(error.sw) == 0x6A88: return
        raise
    raise VaultError('An existing certificate or PIV object was found. The key operation stopped.')


def _empty_key_slot(session, slot):
    try: session.get_slot_metadata(slot)
    except ApduError as error:
        if int(error.sw) == 0x6A88: return
        raise
    raise VaultError('A private key already exists in this slot. It will not be overwritten.')


def _check_target(session, slot, expected_public):
    if expected_public is None:
        _empty_key_slot(session, slot)
        _absent(session, lambda: session.get_certificate(slot))
    else:
        # Metadata is authoritative: certificate absence never proves an empty slot.
        actual = session.get_slot_metadata(slot).public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if piv.b64(actual) != expected_public:
            raise VaultError('The existing key has changed. Inspect the device and confirm the replacement again.')


def create_key(serial, slot, pin, management_key, *, confirmation, progress=lambda _: None):
    return _write_key(serial, slot, pin, management_key, confirmation=confirmation, progress=progress)


def replace_key(serial, slot, pin, management_key, *, confirmation, expected_public, progress=lambda _: None):
    if not expected_public: raise VaultError('A verified existing public key is required for replacement.')
    return _write_key(serial, slot, pin, management_key, confirmation=confirmation,
        expected_public=expected_public, progress=progress)


def _write_key(serial, slot, pin, management_key, *, confirmation, expected_public=None, progress=lambda _: None):
    """Write one selected retired slot after checking its exact current key state."""
    replacing = expected_public is not None
    expected_token = (f'YKA-REPLACE-KEY:{int(serial)}:{int(slot):02X}:' +
        hashlib.sha256(base64.b64decode(expected_public, validate=True)).hexdigest()) if replacing else f'YKA-NEW-KEY:{int(serial)}:{int(slot):02X}'
    if not 0x82 <= int(slot) <= 0x95 or confirmation != expected_token:
        raise VaultError('Explicit confirmation of the device and slot is required.')
    if not pin or (management_key and len(management_key) not in (16, 24, 32)):
        raise VaultError('Enter your PIV PIN and a valid management key, or use PIN-protected management.')
    connection, session = piv.open_session(serial)
    stage = "checking the device"
    try:
        if session.get_serial() != int(serial) or session.version < (5, 8, 0):
            raise VaultError('This key operation requires YubiKey firmware 5.8 or later.')
        if any(m.default_value for m in (session.get_pin_metadata(), session.get_puk_metadata(), session.get_management_key_metadata())):
            raise VaultError('Change the factory-default PIN, PUK and management key using Yubico Authenticator before creating a key.')
        target = SLOT(int(slot))
        _check_target(session, target, expected_public)
        if not management_key and not get_pivman_data(session).has_stored_key:
            raise VaultError('Protect with PIN is not configured. Enable it using Yubico Authenticator, or explicitly choose manual management-key authentication.')
        if management_key and (not isinstance(management_key, bytes) or len(management_key) != session.get_management_key_metadata().key_type.key_len):
            raise VaultError('The management key is unavailable or does not match the device management algorithm.')
        stage = "verifying your PIN"
        progress('Verifying your PIV PIN to authorize the selected slot operation…')
        session.verify_pin(pin)
        if not management_key:
            stage = "reading PIN-protected management credentials"
            management_key = get_pivman_protected_data(session).key
        stage = "authorizing device management"
        progress('Authorizing device management. Touch your YubiKey if it is flashing.')
        if not isinstance(management_key, bytes) or len(management_key) != session.get_management_key_metadata().key_type.key_len:
            raise VaultError('The management key is unavailable or does not match the device management algorithm.')
        session.authenticate(management_key)
        management_key = None
        _check_target(session, target, expected_public)
        stage = 'generating the private key'
        progress('Creating a new P-256 private key inside your YubiKey…')
        public = session.generate_key(target, KEY_TYPE.ECCP256, PIN_POLICY.ALWAYS, TOUCH_POLICY.ALWAYS)
        stage = 'creating its certificate'
        session.verify_pin(pin)
        progress('Please touch your YubiKey to sign the new key certificate.')
        now = datetime.now(timezone.utc)
        cert = generate_self_signed_certificate(session, target, public, 'CN=YKA Vault Key',
            now - timedelta(minutes=5), now + timedelta(days=3650))
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_algorithm_parameters)
        session.put_certificate(target, cert)
        meta = session.get_slot_metadata(target)
        encode = lambda p: p.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        if (encode(meta.public_key) != encode(public) or meta.pin_policy != PIN_POLICY.ALWAYS
            or meta.touch_policy != TOUCH_POLICY.ALWAYS or encode(session.get_certificate(target).public_key()) != encode(public)):
            raise VaultError('The new key could not be verified.')
        return {'serial': int(serial), 'slot': int(slot), 'public_key': piv.b64(encode(public))}
    except Exception as error:
        if isinstance(error, InvalidPinError): reason = "The PIV PIN was rejected. Check your PIN and remaining attempts."
        elif isinstance(error, NotSupportedError): reason = 'This device or library does not support the requested management operation. Check its configuration using Yubico Authenticator.'
        elif isinstance(error, ApduError): reason = 'The YubiKey rejected this step. Check the selected slot, management credentials and touch prompt before retrying.'
        else: reason = str(error) if isinstance(error, VaultError) else 'The device did not complete this step.'
        raise VaultError(f'The key operation stopped while {stage}. {reason} Changes may remain; do not overwrite or reset the slot.') from None
    finally:
        management_key = None; pin = None
        connection.close()

