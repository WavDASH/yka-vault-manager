"""Shared recovery presentation. The manager always rechecks the actual mount."""
RECOVERY_STATES = frozenset(('unmounted-awaiting-cleanup', 'mount-stopping',
    'mounted-supervisor-lost', 'unknown-mount-owner', 'Unknown / orphan mount'))
REMOVABLE_STATES = frozenset(('Unmounted', 'Verification pending', 'Offline', 'Identity changed', 'unmounted-awaiting-cleanup'))


def recovery_hint(record):
    state = record.get('state')
    if state == 'unmounted-awaiting-cleanup':
        return 'The mount is no longer active. Select Clean Up to release its old session, then mount again or remove it from the list.'
    if state == 'mount-stopping':
        return 'SecureFS is still stopping. Close programs using the mount location, then select Recover Mount. Files may still be accessible.'
    if state in RECOVERY_STATES:
        return 'A mount may still be active. Select Recover Mount to check its location and safely unmount it. Do not delete the mounted folder.'
    return ''
