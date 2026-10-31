"""Bounded same-job selection references; terminal success rules are separate."""
from hashlib import sha256
import json
from pathlib import Path
import re
from .capture_inputs import read_private

MAX_SELECTION = 8*1024*1024
SCHEMA = 'a7m4-job-selection-ref/1'


def need(value, message):
    if not value:raise ValueError(message)


def _decode(raw):
    def unique(pairs):
        out={}
        for k,v in pairs:
            need(k not in out,'Duplicate selection key');out[k]=v
        return out
    def finite(value):raise ValueError('Nonfinite selection value')
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=finite)
    need(type(value) is dict,'Selection must be an object')
    return value


def read_selection(root):
    return _decode(read_private(Path(root)/'selection.json',MAX_SELECTION))


def reference(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_SELECTION,'Bounded complete selection bytes required')
    return dict(schema=SCHEMA,path='selection.json',size=len(raw),sha256=sha256(raw).hexdigest())


def resolve_selection(job, root):
    if 'selection_ref' not in job:
        value=job.get('selection',{})
        need(type(value) is dict,'Inline selection must be an object')
        return value
    need('selection' not in job,'Ambiguous inline and referenced selection')
    ref=job['selection_ref']
    need(type(ref) is dict and set(ref)=={'schema','path','size','sha256'}
         and ref['schema']==SCHEMA and ref['path']=='selection.json'
         and type(ref['size']) is int and 0<ref['size']<=MAX_SELECTION
         and type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}',ref['sha256']),
         'Only a bounded fixed same-job selection reference is allowed')
    raw=read_private(Path(root)/'selection.json',MAX_SELECTION)
    need(len(raw)==ref['size'] and sha256(raw).hexdigest()==ref['sha256'],
         'Referenced selection length/SHA changed')
    return _decode(raw)
