"""Read-only provisioning diagnostics and authorized private-key SIGN only.

No generate/reset/change_pin/change_puk/authenticate/change_management_key calls.
"""
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from ykman.pcsc import list_readers, ScardSmartCardConnection, YK_READER_NAME
from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
from yubikit.core.smartcard import ApduError
from yubikit.core import InvalidPinError
from yubikit.piv import PivSession, SLOT, KEY_TYPE
from .windows import VaultError


def b64(data): return base64.b64encode(data).decode('ascii')


def _readers():
    return [reader for reader in list_readers() if YK_READER_NAME in reader.name.lower()]


def _connect(reader):
    # Do not use ykman's automatic shared-mode fallback or agent-killing retry.
    raw = reader.createConnection()
    try:
        return ScardSmartCardConnection(ExclusiveConnectCardConnection(raw))
    except BaseException:
        try: raw.disconnect()
        finally:
            if hasattr(raw, 'release'): raw.release()
        raise


def open_session(serial):
    for reader in _readers():
        connection = None
        try:
            connection = _connect(reader)
            session = PivSession(connection)
            if session.get_serial() == int(serial): return connection, session
        except Exception:
            # A busy unrelated reader must not redirect us to another identity.
            pass
        if connection: connection.close()
    raise VaultError('YubiKey unavailable. Check the smart-card connection.')


def _report(session, serial, *, slots=range(0x82, 0x96), credentials=True):
    report = {'serial': serial, 'firmware': str(session.version), 'slots': []}
    if credentials:
        pin, puk, mgmt = (session.get_pin_metadata(), session.get_puk_metadata(),
                          session.get_management_key_metadata())
        report.update(pin_default=pin.default_value, puk_default=puk.default_value,
            management_default=mgmt.default_value, management_algorithm=mgmt.key_type.name,
            pin_remaining=pin.attempts_remaining, puk_remaining=puk.attempts_remaining)
        from ykman.piv import get_pivman_data
        try: report['management_pin_protected'] = bool(get_pivman_data(session).has_stored_key)
        except Exception: report['management_pin_protected'] = None
    for number in slots:
        slot = SLOT(number)
        try:
            metadata = session.get_slot_metadata(slot)
        except ApduError as error:
            if int(error.sw) == 0x6A88:
                # A missing certificate never proves that the private key is absent.
                # Metadata absence proves no key; a leftover cert still blocks creation.
                try: session.get_certificate(slot)
                except ApduError as cert_error:
                    report['slots'].append({'slot': number, 'empty': True} if int(cert_error.sw) in (0x6A82, 0x6A88)
                        else {'slot': number, 'unknown': True})
                except Exception: report['slots'].append({'slot': number, 'unknown': True})
                else: report['slots'].append({'slot': number, 'unknown': True})
            else:
                report['slots'].append({'slot': number, 'unknown': True})
            continue
        except Exception:
            report['slots'].append({'slot': number, 'unknown': True})
            continue
        entry = {'slot': number, 'empty': False, 'algorithm': metadata.key_type.name,
            'pin_policy': metadata.pin_policy.name, 'touch_policy': metadata.touch_policy.name}
        entry['key_public_der'] = b64(metadata.public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        entry['origin'] = 'Generated on device' if metadata.generated else 'Imported'
        if isinstance(metadata.public_key, ec.EllipticCurvePublicKey) and isinstance(metadata.public_key.curve, ec.SECP256R1):
            entry['public_key'] = b64(metadata.public_key.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))
            try:
                cert = session.get_certificate(slot)
                entry['certificate'] = b64(cert.public_bytes(serialization.Encoding.DER))
                certificate_key = cert.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
                entry['age_compatible_candidate'] = b64(certificate_key) == entry['public_key'] and not any(e.critical and e.oid.dotted_string not in
                    ('1.3.6.1.4.1.41482.3.8',) for e in cert.extensions)
            except Exception:
                entry['age_compatible_candidate'] = False
        report['slots'].append(entry)
    return report


def selected_device(serial, slot, *, enroll=False):
    if int(slot) not in range(0x82, 0x96):
        raise VaultError('No compatible P-256 key in the selected slot.')
    connection, session = open_session(serial)
    try:
        report = _report(session, int(serial), slots=(int(slot),), credentials=enroll)
        if enroll and any(report[name] for name in ('pin_default', 'puk_default', 'management_default')):
            raise VaultError('Factory-default credentials detected. Configure the PIV PIN, PUK and management key using Yubico Authenticator before enrollment.')
        for entry in report['slots']:
            if entry['slot'] == int(slot) and entry.get('public_key') and entry.get('age_compatible_candidate'):
                return {'serial': int(serial), 'slot': int(slot), 'public_key': entry['public_key']}
    finally:
        connection.close()
    raise VaultError('No compatible P-256 key in the selected slot.')


def sign(device, message, pin, progress=lambda _: None):
    connection, session = open_session(device['serial'])
    try:
        public = session.get_slot_metadata(SLOT(device['slot'])).public_key
        encoded = b64(public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))
        if encoded != device['public_key']:
            raise VaultError('YubiKey identity mismatch.')
        progress('Verifying your PIN before signing this vault authorization…')
        session.verify_pin(pin)  # Exactly one caller-authorized attempt; never retry.
        progress('Please touch YubiKey ' + str(device['serial']) + ' to sign this vault authorization.')
        signature = session.sign(SLOT(device['slot']), KEY_TYPE.ECCP256, message, hashes.SHA256())
        public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        progress('YubiKey signature verified. Continuing the operation…')
        return b64(signature)
    except InvalidPinError as error:
        failure = VaultError('The YubiKey PIN is blocked.' if error.attempts_remaining == 0 else 'Incorrect YubiKey PIN.')
        failure.diagnostic = {'code': 'pin_blocked' if error.attempts_remaining == 0 else 'pin_incorrect', 'stage': 'authentication'}
        raise failure from None
    except VaultError: raise
    except InvalidSignature:
        failure = VaultError('The operation failed. See Diagnostics for details.')
        failure.diagnostic = {'code': 'device_failed', 'stage': 'authentication'}
        raise failure from None
    except ApduError as error:
        if int(error.sw) == 0x6983:
            failure = VaultError('The YubiKey PIN is blocked.')
            failure.diagnostic = {'code': 'pin_blocked', 'stage': 'authentication'}
            raise failure from None
        raise VaultError('The YubiKey did not respond. Reconnect it and try again.') from None
    except Exception:
        raise VaultError('The YubiKey did not respond. Reconnect it and try again.') from None
    finally:
        connection.close()
