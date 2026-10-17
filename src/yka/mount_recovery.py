"""Shared recovery presentation. The manager always rechecks the actual mount."""
RECOVERY_STATES = frozenset(('unmounted-awaiting-cleanup', 'mount-stopping',
    'mounted-supervisor-lost', 'unknown-mount-owner', 'Unknown / orphan mount'))
REMOVABLE_STATES = frozenset(('Unmounted', 'Verification pending', 'Offline', 'Identity changed', 'unmounted-awaiting-cleanup'))


def recovery_hint(record):
    state = record.get('state')
    if state == 'unmounted-awaiting-cleanup':
        return 'The vault is unmounted, but its previous session still needs cleanup.'
    if state == 'mount-stopping':
        return 'The vault could not be unmounted. Close files using it and try again.'
    if state in RECOVERY_STATES:
        return 'Mount status is uncertain. Use Recover Mount to check it.'
    return ''
