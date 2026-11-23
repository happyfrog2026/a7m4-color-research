"""Selected modules on one borrowed native channel; no fixed-profile coercion."""
from pathlib import Path
from hashlib import sha256
import os
from .feature_stages import Stages as LeafStages
from . import selected_cumulative as ledger, selected_baseline
from . import looks_program as lp, looks_settings as ls, looks_resource_scope as lr
from . import gate_cumulative as gc, gate_scope as gs, sound_cumulative as sc, sound_scope as ss
from . import program_worker as pw
from .native_actions import NativeActions, _write, _json
from .capture_inputs import read_private
from .device_job import _native_protocol
from .build_scratch import discard_caches


class Stages(LeafStages):
    def __init__(self,channel,root,build_root,body,profile,*,identity,settings_channel,result,
                 receipt_commit,compiler,parent=None,actions_factory=NativeActions,selection,baseline):
        if parent is not None or profile!='selected':raise ValueError('Selected install only; restore uses original backup')
        self.channel=channel;self.root=Path(root);self.build_root=Path(build_root)
        self.body=body;self.profile='selected';self.selection=selection;self.baseline=baseline
        filters=selection['draft']['filters'];self.config=dict(fl23=filters['fl23'],m9=filters['m9'],
            sound=selection['draft']['sound']['mode']=='prepared',slot=1,display_name='M9')
        self.identity=identity;self.settings_channel=settings_channel;self.result=result
        self.receipt_commit=receipt_commit;self.compiler=compiler;self.actions_factory=actions_factory
        self.history=[];self.protocols=[];self.mutated=False;self.index=0
        self.final_checks=[];self.settings_targets=[];self.restoring=False;self.leaves={}
        self.master=ledger.Capsule(root,body,selection,result=result,receipt_commit=receipt_commit)

    def leaf(self,owner):
        if owner in self.leaves:return self.leaves[owner]
        if owner not in ledger.owners(self.selection):raise ValueError('Native owner absent from sealed selection')
        folder=self.root/('C-'+owner);folder.mkdir(mode=0o700)
        common=dict(parent=None,on_change=self.master.callback(owner))
        if owner=='gate':leaf=gc.Capsule(folder,self.body,restoring=False,**common)
        elif owner=='looks-program':leaf=lp.ProgramCapsule(folder,self.body,**common)
        elif owner=='looks-settings':leaf=ls.Capsule(folder,self.body,restoring=False,**common)
        elif owner=='looks-resource':leaf=lr.ResourceCapsule(folder,self.body,**common)
        elif owner=='sound':leaf=sc.Capsule(folder,self.body,gate=self.leaf('gate').value,**common)
        else:raise ValueError('Selected leaf requires its dedicated native transaction')
        self.leaves[owner]=leaf;return leaf

    def gate_forward(self):
        if not self.config['sound']:raise ValueError('Silent selection cannot enable sound Gate')
        fresh=self.images();self._program(gs.program(fresh['ap'],fresh['cp'],'enabled'),gate=True)
        self.final_checks.append(lambda images:gs.need(gs.state(images['cp'])=='enabled','Selected sound Gate differs'))

    def sound(self,prepared=None,*,inverse=False):
        if inverse or not self.config['sound']:raise ValueError('Selected sound forward transaction required')
        fresh=self.images();ticket=ss.forward(fresh['ap'],fresh['cp'],fresh['bank'],prepared,selected=True)
        controls=ticket['controls'];draft=self.selection['draft']['sound']
        if any(controls[k]!=draft[k] for k in ('gain_db','recock_enabled','recock_gap_ms','cutoff_seconds')):
            raise ValueError('Sound controls differ from the final selected snapshot')
        head=bytes.fromhex(ticket['bank']['after_head_hex']);tail=bytes.fromhex(ticket['bank']['after_tail_hex'])
        for role,(offset,capacity) in ss.pin_plan.SLOTS.items():
            ref=self.selection['prepared_ref']['native'][role];length=ticket['native_lengths'][role]
            raw=head[:length] if role=='ka' else tail[offset-ss.ORIGINAL_EOF:offset-ss.ORIGINAL_EOF+length]
            if length!=ref['bytes'] or len(raw)!=length or sha256(raw).hexdigest()!=ref['sha256']:
                raise ValueError('Sound native payload differs from the confirmed final selection')
        self.final_checks.append(lambda images:ss.check(ticket,images,target=True))
        changed=(any(r['before_hex']!=r['after_hex'] for r in ticket['ap_windows']) or
            ticket['bank']['source_eof']!=ticket['bank']['target_eof'] or
            any(ticket['bank']['before_'+k]!=ticket['bank']['after_'+k] for k in ('head_hex','tail_hex')))
        if not changed:return
        folder,build=self._folder('sound');built=ss.build(ticket,build,compiler=self.compiler)
        _write(folder/'ticket.json',_json(ticket));now=self.identity()
        protocol=_native_protocol(ss.Protocol,ticket,dict(pid=now['process_id']),self.result)
        self.protocols.append(protocol);action=self.actions_factory(self.channel,folder/'native');self.history.append(action)
        action.upload_data({row['upload_path']:row['data'] for row in ss.packets(ticket).values()},report_sizes=(ss.REPORT.size,))
        for mode in (0,1,3):
            request=protocol.request(mode,os.urandom(16))
            action.phase(read_private(Path(built['worker']['path']),65535),ss.REQUEST_PATH,request,ss.REPORT_PATH,
                protocol.accept,report_bytes=ss.REPORT.size,
                **({'before_dispatch':lambda:self._attempt('sound',ticket,request)} if mode==1 else {}))
            if mode in (0,3):protocol.confirm(self.images())
        action.clean_packets();self.leaf('sound').confirmed()

    def cutoff_forward(self):
        from . import cutoff_scope
        fresh=self.images();ticket=cutoff_scope.plan(fresh['ap'],fresh['cp'],self.selection['draft']['sound']['cutoff_seconds'])
        self.final_checks.append(lambda images:cutoff_scope.check(ticket,images,target=True))
        if ticket['native_plan'] is None:return
        folder,build=self._folder('cutoff');built=cutoff_scope.build(ticket,build,compiler=self.compiler)
        _write(folder/'ticket.json',_json(ticket));protocol=_native_protocol(cutoff_scope.Protocol,ticket,dict(pid=self.identity()['process_id']),self.result)
        self.protocols.append(protocol);action=self.actions_factory(self.channel,folder/'native');self.history.append(action)
        event=None
        def dispatch(request):
            nonlocal event
            event=dict(body_binding=self.body,ticket=ticket,request_hex=request.hex(),request_sha256=sha256(request).hexdigest(),outcome='ATTEMPTED_UNKNOWN')
            self.master.commit('cutoff',event);self.mutated=True;self.result['persistent_write_phase_attempted']=True;self._commit()
        for mode in (0,1,3):
            request=protocol.request(mode,os.urandom(16))
            action.phase(read_private(Path(built['worker']['path']),65535),pw.REQUEST_PATH,request,pw.RESULT_PATH,
                protocol.accept,report_bytes=pw.REPORT.size,
                **({'before_dispatch':lambda r=request:dispatch(r)} if mode==1 else {}))
            if mode in (0,3):protocol.confirm(self.images())
        action.clean_packets()
        if event is not None:event=dict(event,outcome='C_D_READBACK_VERIFIED');self.master.commit('cutoff',event)

    def prove_original_runtime(self):
        from . import backup_target_runtime as runtime, original_ap_load
        from .native_channel import LIBRARY
        now=self.identity();self.index+=1
        actions=[]
        def factory(channel,output):
            action=self.actions_factory(channel,output);self.history.append(action);actions.append(action);return action
        proof=runtime.verify(self.baseline,self.channel,self.root/('loaded-original-%03d'%self.index),
            compiler=self.compiler,boot_id=now['boot_id'],pid=now['process_id'],endpoint='source',actions_factory=factory)
        self.result['original_loaded_C_proof']=proof;self._commit()
        if len(actions)!=1:raise ValueError('Original loaded-C action tracking differs')
        action=actions[0]
        if not (proof.get('cleanup_safe') is True and proof.get('no_memory_write') is True and proof.get('no_COW') is True
                and not action.failed and not action.unknown_remote_state and not action.owned and self.channel.healthy
                and all(self.channel.peek(p) is None for p in (LIBRARY,original_ap_load.REQUEST_PATH,original_ap_load.RESULT_PATH))):
            raise ValueError('Original loaded-C cleanup or channel is unknown')
        if proof.get('C_loaded_verified') is not True and proof.get('native_status')!=-84:
            raise ValueError('Original AP runtime could not be proved')
        action.feature_attempted=False;action.inspection_complete=True
        if proof.get('C_loaded_verified') is not True:
            raise ValueError('原始文件已匹配，但运行中的程序尚未恢复原始基线。请按安全退出后的提示冷启动，重新进入 MSC 后重试本次配置；尚未写入任何功能。')
        return proof

    def forward(self,*,prepared=None,native_project=None):
        # The complete registered baseline (not just selected modules) is a
        # barrier before any persistent leaf dispatch. F hashes are observations.
        from . import selected_config
        selected_config.validate(self.selection)
        self.result['original_baseline_proof']=selected_baseline.check_live(self.baseline,self.channel,self.settings_channel.capture())
        self._commit();self.prove_original_runtime()
        fresh=self.images();looks=self.config['fl23'] or self.config['m9']
        ls.dependencies(self.settings_channel.capture(),forward=False)
        if looks:lp.plan(fresh['ap'],fresh['cp'],config=self.config)
        if self.config['sound']:
            _,clips=ss.prepared(prepared,selected=True)
            for role,raw in clips.items():
                expected=self.selection['prepared_ref']['native'][role]
                if len(raw)!=expected['bytes'] or sha256(raw).hexdigest()!=expected['sha256']:
                    raise ValueError('Prepared native sound changed before the first dispatch')
        if self.config['m9']:
            import json
            original=json.loads(read_private(Path(self.selection['display_ref']['path'])/'manifest.json',2*1024*1024))
            # The shared transaction freezer returns the manifest FILE, while
            # local planning also accepts a project directory. Preserve both
            # forms; never append manifest.json to an existing manifest file.
            frozen_path=Path(native_project)
            if not frozen_path.is_file():frozen_path=frozen_path/'manifest.json'
            frozen=json.loads(read_private(frozen_path,2*1024*1024))
            original.pop('output_dir',None);frozen.pop('output_dir',None)
            if original!=frozen:raise ValueError('Frozen native icon assets differ from the confirmed project')
        resources=(lr.plan_forward({p:self.channel.file(p) for p in lr.PATHS},icon_project=native_project,owned_playback=False)
            if self.config['m9'] else dict(files=[]))
        if self.config['m9'] and resources.get('display')!=self.selection['display_ref']['display']:
            raise ValueError('Frozen selected display differs before native inspection')
        transactions=self.resources_inspect(resources['files'])
        if looks or self.config['sound']:self.settings(looks=False)
        if self.config['sound']:
            self.gate_forward();self.cutoff_forward();self.sound(prepared)
        else:
            self.final_checks.append(lambda images:gs.need(gs.state(images['cp'])=='disabled','Silent selection requires original disabled Gate'))
        if looks:self.program_forward()
        self.resources_apply(transactions)
        if looks:self.settings(looks=True)
        for ticket in resources['files']:
            self.final_checks.append(lambda images,t=ticket:lr.check(t,self.channel.file(t['target_path']),target=True))
        return dict(stage='SELECTED_C_APPLIED_PENDING_POSTREAD_AND_EXIT',complete=False,
            E_F_restored=False,selection_sha256=self.selection['selection_sha256'],
            resource_files=len(resources['files']),selected_capsule_sha256=self.master.value['capsule_sha256'])

    def verify_final(self,images,settings):
        # Native leaf plans verify their own final C and explicit D. Unselected
        # settings are never replayed; all four planes retain strict CRC parsing.
        for check in self.final_checks:check(images)
        from . import settings_plan as sp
        sp.validate_snapshot(settings)
        for plan in self.settings_targets:
            for record in plan.records:
                attrs=plan.baseline.ram.records[record.chip,record.key].attrs
                for plane in ('ram','saved','bin','bak'):
                    value=getattr(settings,plane).records[record.chip,record.key]
                    expected=record.after_ram if plane=='ram' else record.after_saved
                    if value.attrs!=attrs or len(value.data)!=len(expected) or any(value.data[a:b]!=expected[a:b] for a,b in record.spans):
                        raise ValueError('Selected settings final C differs')
        ls.dependencies(settings,forward=bool(self.config['fl23'] or self.config['m9'] or self.config['sound']))
        return dict(C_D_verified=True,settings_C_D_verified=True,E_F_gate_execution=False)
