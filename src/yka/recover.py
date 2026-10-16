"""Offline CLI fallback using the same verified core; no GUI index or hardware writes."""
import argparse
import getpass
import sys
from .manager import Manager
from .windows import VaultError


def main():
    parser = argparse.ArgumentParser(description='YKA offline recovery')
    commands = parser.add_subparsers(dest='action', required=True)
    restore = commands.add_parser('restore', help='Restore .yka into a new folder')
    restore.add_argument('archive'); restore.add_argument('destination')
    check = commands.add_parser('check', help='Authenticate Keyring and native configuration')
    check.add_argument('root')
    check.add_argument('--trust-existing', action='store_true', help='Acknowledge native folder provenance when no Registry or import proof exists')
    keyring = commands.add_parser('restore-keyring', help='Restore a missing Keyring from its backup')
    keyring.add_argument('root'); keyring.add_argument('backup')
    mount = commands.add_parser('mount', help='Mount until Enter or Ctrl+C, then verify unmount')
    mount.add_argument('root'); mount.add_argument('mount_point')
    mount.add_argument('--trust-existing', action='store_true', help='Acknowledge native folder provenance; does not authenticate archive history')
    args = vars(parser.parse_args())
    if not sys.stdin or not sys.stdin.isatty():
        parser.error('Run in an interactive console. Password pipes are not supported.')
    print('Keep an independent backup of important data.')
    manager = Manager(print)
    # No command-line, environment, file, or stdin-password option.
    password = getpass.getpass('Password: ')
    status = 0
    try:
        action = args.pop('action')
        args['passphrase'] = password
        if action == 'restore':
            if input('Restore the keys and password saved in this backup, including older unlock methods? [y/N] ').strip().lower() != 'y':
                print('Import cancelled.'); return
            args['accept_backup_authorization'] = True
            result = manager.import_(args)
            print('Restored. Identity verified. Source consistency unconfirmed.')
            print(result['path'])
        elif action == 'check':
            from .native import native_call
            from .windows import VaultGuard, safe_path
            root = safe_path(args['root'], must_exist=True)
            with VaultGuard(root) as guard:
                manager._idle(root)
                result = manager._verified(root, args, guard)
            print('Keyring, configuration, and pending import proof verified.')
        elif action == 'restore-keyring':
            manager.restore_keyring(args); print('Keyring restored and verified.')
        elif action == 'mount':
            manager.mount(args)
            args.pop('passphrase', None); password = None
            print('Mounted. Plaintext is accessible.')
            input('Press Enter to unmount. ')
            manager.unmount(args); print('Unmount confirmed.')
    except KeyboardInterrupt:
        print('\nStopping; checking unmount.'); status = 130
    except VaultError as error:
        print(str(error), file=sys.stderr); status = 1
    except Exception:
        print('Recovery failed. Check files, credentials, and mount status.', file=sys.stderr); status = 1
    finally:
        password = None; args.pop('passphrase', None)
        result = manager.security({'event': 'recovery-cli-exit'})
        if result['unmount_failed']:
            print('Unmount failed. Plaintext may remain accessible.', file=sys.stderr); status = 2
    raise SystemExit(status)


if __name__ == '__main__': main()
