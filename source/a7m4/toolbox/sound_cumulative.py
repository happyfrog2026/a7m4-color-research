"""Explicit actual-dispatch Gate+sound C union. No device I/O or F restore."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from . import gate_cumulative, sound_scope as sound
from .capture_inputs import read_private
from .native_actions import _json, _write
from .usb_read import _atomic_json, LOADER_SHA256

SCHEMA='a7m4-gate-sound-union-C/1'


def seal(value):
    value=deepcopy(value);value.pop('capsule_sha256',None)
    value['capsule_sha256']=sha256(_json(value)).hexdigest();return value


def validate(value,body=None):
    sound.need(type(value) is dict and value.get('schema')==SCHEMA and seal(value)==value,'Sound union capsule integrity differs')
    sound.need(body is None or value['body_binding']==body,'Sound union capsule belongs to another body')
    sound.need(value['firmware']=='6.02' and value['loader_sha256']==LOADER_SHA256
        and value['E_F_restore_promised'] is False and value['cache_restore']=='NORMAL_REBUILD','Sound union scope differs')
    gate_cumulative.validate(value['gate'],value['body_binding'])
    rows=value['sound_events'];sound.need(type(rows) is list and len(rows)<=1,'Only first stock sound install is supported')
    original=value['sound_original']
    if not rows:sound.need(original is None,'Unattempted sound must not claim C ownership')
    else:
        e=rows[0];sound.need(e['outcome'] in ('ATTEMPTED_UNKNOWN','C_READBACK_VERIFIED')
            and type(e['request_sha256']) is str and len(e['request_sha256'])==64
            and type(e['native_ticket_id']) is str and len(e['native_ticket_id'])==64,'Sound dispatch identity differs')
        sound.need(original==e['original'] and original['eof']==sound.ORIGINAL_EOF
            and original['ap_words']==[w.hex() for w in sound.STOCK_WORDS]
            and len(bytes.fromhex(original['head_hex']))==256,'Earliest sound original C differs')
        lengths=original['native_lengths'];sound.need(set(lengths)==set(sound.pin_plan.SLOTS)
            and all(type(lengths[r]) is int and 0<lengths[r]<=sound.pin_plan.SLOTS[r][1] and lengths[r]%64==0 for r in lengths),
            'Registered sound descriptor lengths differ')
        sound.need(original['installed_ap_words']==[w.hex() for w in sound.pin_plan._ap_after(lengths)],'Registered sound runtime endpoint differs')
    return deepcopy(value)


def load(path,body=None):return validate(json.loads(read_private(Path(path),2*1024*1024)),body)


class Capsule:
    def __init__(self,root,body,*,gate=None,parent=None,result=None,on_change=None):
        self.path=Path(root)/'gate-sound-C-capsule.private.json';self.result=result
        self.on_change=on_change
        if parent is not None:self.value=validate(parent,body)
        else:
            gate=gate_cumulative.validate(gate,body)
            self.value=seal(dict(schema=SCHEMA,body_binding=body,firmware='6.02',loader_sha256=LOADER_SHA256,
                gate=gate,sound_original=None,sound_events=[],E_F_restore_promised=False,cache_restore='NORMAL_REBUILD',
                coverage='Gate-plus-first-stock-sound-explicit-dispatch-history'))
        self.persist()
    def persist(self):
        self.value=seal(self.value);validate(self.value);_atomic_json(self.path,self.value)
        raw=read_private(self.path,2*1024*1024)
        if self.result is not None:self.result['C_capsule_ref']=dict(path=self.path.name,size=len(raw),sha256=sha256(raw).hexdigest())
        if self.on_change is not None:
            committed=self.on_change(deepcopy(self.value))
            sound.need(committed is None or type(committed) is int and committed==0,'Master sound C commit failed before dispatch')
    def dispatch(self,plan,request):
        sound.validate(plan);sound.need(plan['direction']=='forward' and not self.value['sound_events'],'No sound replay/update in first-install profile')
        original=dict(ap_words=[r['before_hex'] for r in plan['ap_windows']],head_hex=plan['bank']['before_head_hex'],
            eof=plan['bank']['source_eof'],installed_ap_words=[r['after_hex'] for r in plan['ap_windows']],
            native_lengths=plan['native_lengths'])
        event=dict(outcome='ATTEMPTED_UNKNOWN',original=original,native_ticket_id=plan['plan_id'],request_sha256=sha256(request).hexdigest())
        _write(self.path.parent/'sound-C-dispatch-intent.json',_json(event))
        self.value['sound_original']=original;self.value['sound_events'].append(event);self.persist()
    def confirmed(self):
        sound.need(len(self.value['sound_events'])==1,'Missing sound dispatch')
        self.value['sound_events'][0]['outcome']='C_READBACK_VERIFIED';self.persist()
