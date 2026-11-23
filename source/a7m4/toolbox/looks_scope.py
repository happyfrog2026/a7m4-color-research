"""Three fixed GUI experiments; local program plans, no device/session I/O."""
from copy import deepcopy
from pathlib import Path

from . import looks_program
from .capture_inputs import read_private
from .device_job import complete_capture

CONFIGS=(dict(id='fl23-only',fl23=True,m9=False,sound=False,slot=1,display_name='M9'),
         dict(id='custom1-m9',fl23=False,m9=True,sound=False,slot=1,display_name='M9'),
         dict(id='full',fl23=True,m9=True,sound=True,slot=1,display_name='M9'))
FIXED_ORDER=('Gate-and-M9-sound','looks-programs','looks-resources','AP55-and-business-settings','final-C-D-readback','OriginalWBI','sole-STOP-and-normal-MSC')


def configurations():return deepcopy(CONFIGS)


def capture_plan(capture_path,config):
    if isinstance(config,str):config=next((x for x in CONFIGS if x['id']==config),None)
    looks_program.need(config in CONFIGS,'Only the three fixed offline experiments are prepared')
    capture,_=complete_capture(capture_path);root=Path(capture['snapshot_dir'])
    ap=read_private(root/'appFw.so',looks_program.LIMITS['ap']);cp=read_private(root/'CPAPP-B.BIN',looks_program.LIMITS['cp'])
    ticket=looks_program.plan(ap,cp,config=config)
    return dict(schema='a7m4-looks-C-D-experiment/1',config=deepcopy(config),body_binding=capture['body_binding'],
        capture_receipt=str(Path(capture_path).absolute()),program=ticket,fixed_order=list(FIXED_ORDER),
        resources_external_module='looks_resource_scope',settings_external_module='looks_settings',
        E_F_gate_execution=False,cache_restore='NORMAL_REBUILD',camera_io=False,device_validation='not-performed')
