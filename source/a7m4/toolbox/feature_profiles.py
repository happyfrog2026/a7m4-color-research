"""The three explicitly selected validation profiles, never a feature matrix."""
from copy import deepcopy
from .policy import filter_selection

PROFILES=('fl23','custom1-m9','all-current')
OWNER_ORDER=('looks-program','looks-settings','looks-resource','gate','sound')


def fixed_config(profile):
    """Translate the public enum to the three leaf owners' reviewed contract."""
    if profile not in PROFILES:raise ValueError('Unsupported feature profile')
    return dict(id={'fl23':'fl23-only','custom1-m9':'custom1-m9','all-current':'full'}[profile],
        fl23=profile!='custom1-m9',m9=profile!='fl23',sound=profile=='all-current',slot=1,display_name='M9')


def normalize(profile,configuration):
    if profile not in PROFILES:raise ValueError('Only fl23/custom1-m9/all-current profiles are supported')
    config=filter_selection(configuration)
    value=deepcopy(config)
    value['include_fl2']=value['include_fl3']=profile!='custom1-m9'
    for row in value['slots']:row['selected']=row['slot']==1 and profile!='fl23'
    if profile!='fl23':
        value['slots'][0].update(recipe='m9')
    return dict(schema='a7m4-fixed-feature-profile/1',profile=profile,filters=filter_selection(value),
        custom1_ST='automatic-if-required' if profile!='fl23' else 'preserve',
        other_custom_slots='preserve',sound=profile=='all-current',Gate=profile=='all-current',
        color_calibration='DEFERRED',other_combinations='NOT_SUPPORTED')


def owners(profile):
    if profile not in PROFILES:raise ValueError('Unsupported feature profile')
    return OWNER_ORDER if profile=='all-current' else ('looks-program','looks-settings','gate') if profile=='fl23' else OWNER_ORDER[:4]
