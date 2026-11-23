"""Fixed-profile master C manifest. Leaf owners retain their finite contracts.

No byte patcher, camera discovery, historical F equality or raw settings replay.
A leaf's durable update is committed here before its imminent native dispatch.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from .feature_profiles import PROFILES,owners
from .capture_inputs import read_private
from .native_actions import _json
from .usb_read import _atomic_json,LOADER_SHA256

SCHEMA='a7m4-feature-union-C/1'
FILENAME='feature-union-C-capsule.private.json'
MAXIMUM=8*1024*1024


def leaf_validators():
    from . import looks_program,looks_settings,looks_resource_scope,gate_cumulative,sound_cumulative
    return {'looks-program':looks_program.validate_capsule,'looks-settings':looks_settings.validate,
        'looks-resource':looks_resource_scope.validate_capsule,'gate':gate_cumulative.validate,
        'sound':sound_cumulative.validate}


def need(value,message):
    if not value:raise ValueError(message)


def seal(value):
    value=deepcopy(value);value.pop('capsule_sha256',None)
    value['capsule_sha256']=sha256(_json(value)).hexdigest();return value


def validate(value,body,validators):
    need(type(value) is dict and value.get('schema')==SCHEMA and seal(value)==value,'Feature C capsule integrity differs')
    need(value.get('body_binding')==body and value.get('firmware')=='6.02' and value.get('loader_sha256')==LOADER_SHA256,'Feature C capsule body/firmware/loader differs')
    profile=value.get('profile');need(profile in PROFILES,'Fixed feature profile required')
    need(value.get('E_F_restore_promised') is False and value.get('cache_restore')=='NORMAL_REBUILD','Feature C restore contract differs')
    children=value.get('children');need(type(children) is dict and set(children)<=set(owners(profile)),'Unexpected C owner outside selected profile')
    need(type(value.get('revision')) is int and 0<=value['revision']<=8192,'Bounded C update count required')
    for owner,child in children.items():
        need(owner in validators and callable(validators[owner]),'Finite leaf validator required: '+owner)
        need(type(child) is dict and set(child)=={'value','sha256'} and sha256(_json(child['value'])).hexdigest()==child['sha256'],'C owner manifest hash differs')
        need(type(child['value']) is dict and child['value'].get('body_binding')==body,'C leaf belongs to another body')
        if owner=='gate' and profile!='all-current':
            need('cp' not in child['value'].get('originals',{}),'Single looks profiles may own AP55 only, never CP sound Gate')
        validators[owner](child['value'],body)
    return deepcopy(value)


def load(path,body,validators):return validate(json.loads(read_private(Path(path),MAXIMUM)),body,validators)


def _extends(owner,old,new):
    """A later leaf commit cannot erase an earlier actual-dispatch claim."""
    key='sound_events' if owner=='sound' else 'events'
    before,after=old[key],new[key]
    need(len(after)>=len(before),'C dispatch history cannot shrink')
    for first,later in zip(before,after):
        immutable=lambda event:{k:v for k,v in event.items() if k!='outcome'}
        need(immutable(first)==immutable(later),'Earlier C dispatch identity/preimage cannot change')
        need(first['outcome']==later['outcome'] or first['outcome']=='ATTEMPTED_UNKNOWN'
            and later['outcome'] in ('C_READBACK_VERIFIED','C_D_READBACK_VERIFIED'),
            'C dispatch outcome cannot regress')
    if owner=='looks-resource':
        for path,original in old['originals'].items():
            current=new['originals'].get(path)
            need(current is not None and current['eof']==original['eof'],'Earliest resource EOF cannot change')
            need(current['appends'][:len(original['appends'])]==original['appends'],'Actual owned append history cannot change')
            bytes_now={w['offset']+i:b for w in current['windows'] for i,b in enumerate(bytes.fromhex(w['hex']))}
            need(all(bytes_now.get(w['offset']+i)==b for w in original['windows'] for i,b in enumerate(bytes.fromhex(w['hex']))),
                'Earliest resource C bytes cannot change')


class Capsule:
    def __init__(self,root,body,profile,*,validators,result=None,receipt_commit=None,parent=None):
        need(profile in PROFILES,'Only fixed profiles admitted')
        self.path=Path(root)/FILENAME;self.body=body;self.validators=validators;self.result=result;self.receipt_commit=receipt_commit
        self.value=(validate(parent,body,validators) if parent is not None else seal(dict(schema=SCHEMA,
            body_binding=body,firmware='6.02',loader_sha256=LOADER_SHA256,profile=profile,
            E_F_restore_promised=False,cache_restore='NORMAL_REBUILD',children={},revision=0)))
        need(self.value['profile']==profile,'C capsule cannot change profile')
        self.persist()

    def persist(self):
        self.value=seal(self.value);validate(self.value,self.body,self.validators)
        encoded=_json(self.value);need(len(encoded)<=MAXIMUM,'Feature C capsule capacity exceeded before dispatch')
        _atomic_json(self.path,self.value)
        actual=read_private(self.path,MAXIMUM);need(actual==encoded,'Durable feature C reopen differs')
        if self.result is not None:self.result['C_capsule_ref']=dict(path=FILENAME,size=len(actual),sha256=sha256(actual).hexdigest())
        if self.receipt_commit is not None:
            committed=self.receipt_commit()
            need(committed is None or type(committed) is int and committed==0,'Master receipt commit failed before dispatch')

    def commit(self,owner,value):
        """Leaf callback: success is required BEFORE a C transport call."""
        need(owner in owners(self.value['profile']) and owner in self.validators,'Unselected feature owner')
        need(type(value) is dict and value.get('body_binding')==self.body,'C leaf body differs')
        self.validators[owner](value,self.body)
        previous=self.value['children'].get(owner)
        if previous is not None:_extends(owner,previous['value'],value)
        self.value['children'][owner]=dict(value=deepcopy(value),sha256=sha256(_json(value)).hexdigest())
        self.value['revision']+=1;self.persist()

    def callback(self,owner):
        need(owner in owners(self.value['profile']),'Unselected owner callback')
        return lambda value:self.commit(owner,value)
