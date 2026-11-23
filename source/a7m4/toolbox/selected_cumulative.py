"""Durable actual-dispatch ledger for one sealed selected configuration."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from . import feature_cumulative as legacy
from .capture_inputs import read_private
from .native_actions import _json
from .usb_read import _atomic_json, LOADER_SHA256

SCHEMA='a7m4-selected-union-C/1'
FILENAME='selected-union-C.private.json'
MAXIMUM=8*1024*1024


def seal(value):
    value=deepcopy(value);value.pop('capsule_sha256',None)
    value['capsule_sha256']=sha256(_json(value)).hexdigest();return value


def owners(selection):
    draft=selection['draft'];look=draft['filters'];result=[]
    if look['fl23'] or look['m9']:result+=['looks-program','looks-settings']
    if look['m9']:result+=['looks-resource']
    if look['fl23'] or look['m9'] or draft['sound']['mode']=='prepared':result+=['gate']
    if draft['sound']['mode']=='prepared':result+=['sound','cutoff']
    return tuple(result)


def validate(value,body,selection):
    if (type(value) is not dict or value.get('schema')!=SCHEMA or seal(value)!=value or
            value.get('body_binding')!=body or value.get('firmware')!='6.02' or
            value.get('loader_sha256')!=LOADER_SHA256 or
            value.get('selection_sha256')!=selection['selection_sha256'] or
            value.get('E_F_restore_promised') is not False or
            value.get('cache_restore')!='NORMAL_REBUILD'):
        raise ValueError('Selected actual-dispatch ledger binding differs')
    children=value.get('children');validators=legacy.leaf_validators()
    if type(children) is not dict or not set(children)<=set(owners(selection)):
        raise ValueError('Unselected native owner in selected ledger')
    if type(value.get('revision')) is not int or not 0<=value['revision']<=8192:
        raise ValueError('Selected ledger update limit differs')
    for owner,child in children.items():
        if set(child)!={'value','sha256'} or sha256(_json(child['value'])).hexdigest()!=child['sha256']:
            raise ValueError('Selected leaf integrity differs')
        if owner=='cutoff':
            from . import cutoff_scope
            item=child['value'];cutoff_scope.validate(item['ticket'])
            from . import program_worker
            request=bytes.fromhex(item['request_hex']);fields=program_worker.REQUEST.unpack(request)
            if (sha256(request).hexdigest()!=item['request_sha256'] or fields[1]!=1 or
                    fields[4]!=bytes.fromhex(item['ticket']['native_plan']['plan_id']) or
                    item['ticket']['target_seconds']!=selection['draft']['sound']['cutoff_seconds']):
                raise ValueError('Cutoff actual native request or final selection differs')
            if (item.get('body_binding')!=body or item.get('outcome') not in ('ATTEMPTED_UNKNOWN','C_D_READBACK_VERIFIED') or
                    len(item.get('request_sha256',''))!=64):raise ValueError('Cutoff dispatch binding differs')
        else:
            validators[owner](child['value'],body)
            if owner=='gate' and selection['draft']['sound']['mode']=='none' and 'cp' in child['value']['originals']:
                raise ValueError('Silent selection cannot own CP sound Gate')
            if owner=='looks-program':
                for event in child['value']['events']:
                    intent=event['ticket']['config']
                    if any(intent[k]!=selection['draft']['filters'][k] for k in ('fl23','m9')):
                        raise ValueError('Looks actual dispatch differs from final selection')
    return deepcopy(value)


class Capsule:
    def __init__(self,root,body,selection,*,result,receipt_commit):
        self.path=Path(root)/FILENAME;self.body=body;self.selection=selection
        self.result=result;self.receipt_commit=receipt_commit
        self.value=seal(dict(schema=SCHEMA,body_binding=body,firmware='6.02',loader_sha256=LOADER_SHA256,
            selection_sha256=selection['selection_sha256'],children={},revision=0,
            cache_restore='NORMAL_REBUILD',E_F_restore_promised=False))
        self.persist()
    def persist(self):
        self.value=seal(self.value);validate(self.value,self.body,self.selection)
        raw=_json(self.value)
        if len(raw)>MAXIMUM:raise ValueError('Selected ledger capacity exceeded before dispatch')
        _atomic_json(self.path,self.value)
        if read_private(self.path,MAXIMUM)!=raw:raise ValueError('Selected durable ledger reopen differs')
        self.result['selected_C_ref']=dict(path=FILENAME,size=len(raw),sha256=sha256(raw).hexdigest())
        committed=self.receipt_commit()
        if committed is not None and (type(committed) is not int or committed!=0):
            raise ValueError('Selected ledger receipt commit failed before dispatch')
    def commit(self,owner,value):
        if owner not in owners(self.selection):raise ValueError('Unselected leaf cannot claim C')
        previous=self.value['children'].get(owner)
        if previous is not None and owner!='cutoff':legacy._extends(owner,previous['value'],value)
        if previous is not None and owner=='cutoff':
            old=previous['value']
            if any(value[k]!=old[k] for k in old if k!='outcome'):
                raise ValueError('Cutoff actual dispatch identity cannot change')
            if old['outcome']=='C_D_READBACK_VERIFIED' and value['outcome']!=old['outcome']:
                raise ValueError('Cutoff proof cannot regress')
        self.value['children'][owner]=dict(value=deepcopy(value),sha256=sha256(_json(value)).hexdigest())
        self.value['revision']+=1;self.persist()
    def callback(self,owner):return lambda value:self.commit(owner,value)
