"""Finite, rebuilding authority dispatch for shared native restore adapters.

No caller-supplied windows gain permission by looking like an old plan.
Unknown schemas fail before a backend or compiler is constructed.
"""


def validate_plan(plan):
    if type(plan) is not dict:
        raise ValueError('Registered restore authority schema required')
    schema = plan.get('schema')
    if schema == 'a7m4-original-backup-diff/1':
        from .original_restore import validate_plan as validate
    elif schema == 'a7m4-backup-target-execution/1':
        from .backup_target_execution import validate_plan as validate
    else:
        raise ValueError('Unknown restore authority schema')
    return validate(plan)
