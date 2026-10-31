"""Finite feature stages on one borrowed, exclusively owned service channel.

The caller owns body/boot admission, the initial complete backup, lifecycle,
WBI, STOP and normal MSC. No stage here discovers or reconnects a device.
Unknown native outcomes propagate; no stage retries or changes native profile.
"""
from pathlib import Path
from hashlib import sha256
import os
import uuid

from . import feature_cumulative as fc, feature_profiles as fp
from . import looks_program as lp, looks_settings as ls, looks_resource_scope as lr
from . import looks_resource_restore as rr
from . import gate_cumulative as gc, gate_scope as gs, sound_cumulative as sc, sound_scope as ss
from . import settings_plan as sp, settings_archive, save_effects, program_worker as pw
from .capture_inputs import read_private
from .device_job import Journal, _native_protocol
from .native_actions import NativeActions, _write, _json
from .settings_job import SettingsJob
from .build_scratch import discard_caches


class Stages:
    def __init__(self,channel,root,build_root,body,profile,*,identity,settings_channel,
                 result,receipt_commit,compiler,parent=None,actions_factory=NativeActions):
        self.channel=channel;self.root=Path(root);self.build_root=Path(build_root)
        self.body=body;self.profile=profile;self.config=fp.fixed_config(profile)
        self.identity=identity;self.settings_channel=settings_channel;self.result=result
        self.receipt_commit=receipt_commit;self.compiler=compiler;self.actions_factory=actions_factory
        self.history=[];self.protocols=[];self.mutated=False;self.index=0
        self.final_checks=[];self.settings_targets=[]
        self.master=fc.Capsule(root,body,profile,validators=fc.leaf_validators(),result=result,
            receipt_commit=receipt_commit,parent=parent)
        self.restoring=parent is not None;self.leaves={}

    def child(self,owner):
        return self.master.value['children'].get(owner,{}).get('value')

    def leaf(self,owner):
        if owner in self.leaves:return self.leaves[owner]
        fc.need(owner in fp.owners(self.profile),'Feature outside selected profile')
        folder=self.root/('C-'+owner);folder.mkdir(mode=0o700)
        common=dict(parent=self.child(owner),on_change=self.master.callback(owner))
        if owner=='gate':leaf=gc.Capsule(folder,self.body,restoring=self.restoring,**common)
        elif owner=='looks-program':leaf=lp.ProgramCapsule(folder,self.body,**common)
        elif owner=='looks-settings':leaf=ls.Capsule(folder,self.body,restoring=self.restoring,**common)
        elif owner=='looks-resource':leaf=lr.ResourceCapsule(folder,self.body,**common)
        elif owner=='sound':
            leaf=sc.Capsule(folder,self.body,gate=self.leaf('gate').value,**common)
        else:raise ValueError('Unknown fixed owner')
        self.leaves[owner]=leaf;return leaf

    def images(self):return {role:self.channel.file(path) for role,path in ss.PATHS.items()}

    def _commit(self):
        value=self.receipt_commit()
        fc.need(value is None or type(value) is int and value==0,'Feature receipt did not confirm durable commit')

    def _folder(self,label):
        self.index+=1;name='%03d-%s'%(self.index,label)
        folder=self.root/name;folder.mkdir(mode=0o700)
        return folder,self.build_root/name

    def _attempt(self,owner,ticket,request,*,inverse=False):
        if not inverse:
            leaf=self.leaf(owner)
            (leaf.program_dispatch if owner=='gate' else leaf.dispatch)(ticket,request)
        else:
            _write(self.root/('inverse-dispatch-'+uuid.uuid4().hex+'.json'),_json(dict(owner=owner,
                request_sha256=sha256(request).hexdigest(),request_hex=request.hex(),
                ticket_sha256=sha256(_json(ticket)).hexdigest(),outcome='ATTEMPTED_UNKNOWN')))
        self.mutated=True;self.result['persistent_write_phase_attempted']=True
        self._commit()

    def _program(self,ticket,*,gate=False,inverse=False):
        if ticket is None or not gate and ticket['native_plan'] is None:return
        folder,build=self._folder('gate' if gate else 'looks-program')
        built=(pw.build_program_worker(ticket,build,compiler=self.compiler) if gate else lp.build(ticket,build,compiler=self.compiler))
        discard_caches(build)
        protocol_type=(gc.RestoreProtocol if inverse else gs.GateProtocol) if gate else lp.Protocol
        now=self.identity();process=dict(pid=now['process_id'])
        protocol=_native_protocol(protocol_type,ticket,process,self.result);self.protocols.append(protocol)
        action=self.actions_factory(self.channel,folder/'native');self.history.append(action)
        _write(folder/'ticket.json',_json(ticket))
        for mode in ((0,1,3) if gate else ticket['native_mode_order']):
            request=protocol.request(mode,os.urandom(16))
            dispatch=(lambda:self._attempt('gate' if gate else 'looks-program',ticket,request,inverse=inverse)) if mode in (1,2) else None
            action.phase(read_private(Path(built['worker']['path']),65535),pw.REQUEST_PATH,request,pw.RESULT_PATH,
                protocol.accept,report_bytes=pw.REPORT.size,**({'before_dispatch':dispatch} if dispatch else {}))
            if mode in (0,3):
                paths={}
                for role in ('ap','cp'):
                    path=folder/('%d-%s.bin'%(mode,role));_write(path,self.channel.file(ss.PATHS[role]));paths[role]=path
                protocol.confirm_readback(paths)
        action.clean_packets()
        if not inverse:
            if gate:self.leaf('gate').confirmed('cp')
            else:self.leaf('looks-program').confirmed({r:paths[r] for r in ('ap','cp')})

    def program_forward(self):
        fresh=self.images();ticket=lp.plan(fresh['ap'],fresh['cp'],config=self.config)
        # An existing program may need no C write while its resource labels
        # still change. Retain an empty, validated leaf for the later native
        # AP-D load inspection; it grants no program byte ownership.
        self.leaf('looks-program')
        self._program(ticket);self.final_checks.append(lambda images:lp.check(ticket,images,target=True))

    def gate_forward(self):
        fc.need(self.profile=='all-current','CP Gate not selected')
        fresh=self.images();self._program(gs.program(fresh['ap'],fresh['cp'],'enabled'),gate=True)
        self.final_checks.append(lambda images:gs.need(gs.state(images['cp'])=='enabled','Final Gate C differs'))

    def program_restore(self):
        original=self.child('looks-program')
        if original is None:return
        fresh=self.images()
        for ticket in lp.restore(fresh['ap'],fresh['cp'],original):
            self._program(ticket,inverse=True)
        def check_original(images):
            lp.dependencies(images['ap'],images['cp'],'m9' if any(e['ticket']['profile']=='m9' for e in original['events']) else 'fl23')
            for role,rows in original['originals'].items():
                for row in rows:
                    raw=bytes.fromhex(row['before_hex']);at=row['offset']
                    fc.need(images[role][at:at+len(raw)]==raw,'Final original looks program C differs')
        self.final_checks.append(check_original)

    def gate_restore(self):
        original=self.child('gate')
        if original is None:return
        fresh=self.images();self._program(gc.cp_program(fresh['ap'],fresh['cp'],original['originals']),gate=True,inverse=True)
        def check_gate(images):
            gs.dependencies(images['ap'],images['cp']);gc.check_cp_target(images['cp'],original['originals'])
        self.final_checks.append(check_gate)

    def settings(self,*,looks,inverse=False):
        owner='looks-settings' if looks else 'gate';original=self.child(owner)
        if inverse and (original is None or not original['originals']):return
        if inverse and not looks and 'ap55' not in original['originals']:return
        fresh=self.settings_channel.capture();now=self.identity()
        binding=dict(identity=self.body['serial_sha256'],boot_id=now['boot_id'],nonce=os.urandom(16).hex())
        if looks:
            plan=(ls.plan_restore(fresh,original,**binding) if inverse else
                ls.plan_forward(fresh,fl23=self.config['fl23'],m9=self.config['m9'],**binding))
        else:
            plan=(gc.settings_plan(fresh,original['originals'],**binding) if inverse else
                sp.plan_ap55(fresh,save_effects_policy=save_effects.NATIVE51,**binding))
        folder,_=self._folder('looks-settings' if looks else 'ap55')
        settings_archive.save_snapshot(fresh,folder/'before')
        leaf=self.leaf(owner)
        def dispatch(observation):
            if not inverse:(leaf.dispatch if looks else leaf.settings_dispatch)(plan,observation)
            self.mutated=True;self.result['persistent_write_phase_attempted']=True;self._commit()
        def bind(p):
            return dict(identity=p.identity,boot_id=self.identity()['boot_id'],nonce=p.nonce,
                model='ILCE-7M4',firmware='6.02',exclusive_owner=True)
        previous=self.settings_channel.before_mutation_dispatch
        self.settings_channel.before_mutation_dispatch=dispatch
        try:
            job=SettingsJob(self.settings_channel,bind=bind,journal=Journal(folder/'wire'),forward_observation_only=True)
            job.release(plan,dict(schema='a7m4-toolbox-settings-release/1',plan_id=plan.plan_id,identity=plan.identity,
                boot_id=plan.boot_id,nonce=plan.nonce,backup_verified=True,program_dependencies_verified=True,
                user_risk_confirmation_fresh=True,release_gate='RELEASED'))
            value=job.execute(plan)
            settings_archive.save_snapshot(job.verified_snapshot,folder/'after')
            if not inverse:
                if looks:leaf.confirmed(plan,job.verified_snapshot)
                else:leaf.confirmed('ap55')
            self.result.setdefault('settings_results',[]).append(value)
            self.settings_targets.append(plan)
        finally:self.settings_channel.before_mutation_dispatch=previous

    def sound(self,prepared=None,*,inverse=False):
        if inverse:
            leaf=self.child('sound')
            if leaf is None or leaf['sound_original'] is None:return
        else:fc.need(self.profile=='all-current','Sound not selected')
        fresh=self.images()
        ticket=(ss.restore(fresh['ap'],fresh['cp'],fresh['bank'],leaf['sound_original']) if inverse else
            ss.forward(fresh['ap'],fresh['cp'],fresh['bank'],prepared))
        self.final_checks.append(lambda images:ss.check(ticket,images,target=True))
        changed=(any(r['before_hex']!=r['after_hex'] for r in ticket['ap_windows']) or
            ticket['bank']['source_eof']!=ticket['bank']['target_eof'] or
            any(ticket['bank']['before_'+k]!=ticket['bank']['after_'+k] for k in ('head_hex','tail_hex')))
        if not changed:return
        folder,build=self._folder('sound');built=ss.build(ticket,build,compiler=self.compiler)
        _write(folder/'ticket.json',_json(ticket))
        now=self.identity();protocol=_native_protocol(ss.Protocol,ticket,dict(pid=now['process_id']),self.result)
        self.protocols.append(protocol);action=self.actions_factory(self.channel,folder/'native');self.history.append(action)
        action.upload_data({row['upload_path']:row['data'] for row in ss.packets(ticket).values()},report_sizes=(ss.REPORT.size,))
        for mode in (0,1,3):
            request=protocol.request(mode,os.urandom(16))
            action.phase(read_private(Path(built['worker']['path']),65535),ss.REQUEST_PATH,request,ss.REPORT_PATH,
                protocol.accept,report_bytes=ss.REPORT.size,
                **({'before_dispatch':lambda:self._attempt('sound',ticket,request,inverse=inverse)} if mode==1 else {}))
            if mode in (0,3):protocol.confirm(self.images())
        action.clean_packets()
        if not inverse:self.leaf('sound').confirmed()

    def resources_inspect(self,plans):
        """Inspect every selected source before granting any resource write."""
        transactions=[]
        for ticket in plans:
            if ticket['native_plan'] is None:continue
            folder,build=self._folder('resource');built=lr.build(ticket,build,compiler=self.compiler)
            discard_caches(build)
            _write(folder/'ticket.json',_json(ticket))
            protocol=_native_protocol(lr.Protocol,ticket,dict(pid=self.identity()['process_id']),self.result)
            self.protocols.append(protocol);action=self.actions_factory(self.channel,folder/'native');self.history.append(action)
            action.phase(read_private(Path(built['worker']['path']),65535),lr.REQUEST_PATH,
                protocol.request(0,os.urandom(16)),lr.REPORT_PATH,protocol.accept,report_bytes=lr.REPORT_BYTES)
            raw=self.channel.file(ticket['target_path']);_write(folder/'before.bin',raw);protocol.confirm_readback(raw)
            transactions.append((ticket,built,protocol,action,folder))
        return transactions

    def resources_apply(self,transactions,*,inverse=False):
        for ticket,built,protocol,action,folder in transactions:
            for mode in (1,3):
                request=protocol.request(mode,os.urandom(16))
                action.phase(read_private(Path(built['worker']['path']),65535),lr.REQUEST_PATH,request,lr.REPORT_PATH,
                    protocol.accept,report_bytes=lr.REPORT_BYTES,
                    **({'before_dispatch':lambda:self._attempt('looks-resource',ticket,request,inverse=inverse)} if mode==1 else {}))
                if mode==3:
                    raw=self.channel.file(ticket['target_path']);_write(folder/'after.bin',raw);protocol.confirm_readback(raw)
                    if not inverse:self.leaf('looks-resource').confirmed(ticket,raw)
            action.clean_packets()

    def verify_final(self,images,settings):
        for check in self.final_checks:check(images)
        # Explicit AP55 changes may occur after a looks transaction. Verify
        # each owned target C, then the final dependency state, rather than
        # treating that sanctioned later prerequisite change as F corruption.
        targets={}
        for plan in self.settings_targets:
            for record in plan.records:
                targets[record.chip,record.key]=(record,plan.baseline.ram.records[record.chip,record.key].attrs)
        for pair,(record,attrs) in targets.items():
            for plane in ('ram','saved','bin','bak'):
                value=getattr(settings,plane).records[pair];actual=value.data
                expected=record.after_ram if plane=='ram' else record.after_saved
                fc.need(value.attrs==attrs and len(actual)==len(expected) and
                    all(actual[a:b]==expected[a:b] for a,b in record.spans),'Final settings C differs')
        ls.dependencies(settings,forward=not self.restoring)
        return dict(C_D_verified=True,settings_C_D_verified=True,E_F_gate_execution=False)

    def forward(self,*,prepared=None,native_project=None):
        """Fixed three-profile order; result is not a service-exit grant."""
        fc.need(not self.restoring,'Forward cannot consume an inverse capsule')
        fresh=self.images();lp.plan(fresh['ap'],fresh['cp'],config=self.config)
        ls.dependencies(self.settings_channel.capture(),forward=False)
        if self.config['sound']:
            fc.need(prepared is not None,'Full profile needs the reviewed prepared M9 sound pack')
            ss.prepared(prepared)
        resources=lr.plan_resources({p:self.channel.file(p) for p in lr.PATHS} if self.config['m9'] else {},
            None,self.config,native_project)
        expected=self.result.get('selection',{}).get('display')
        if expected is not None:fc.need(resources.get('display')==expected,'Frozen display selection differs before native resource inspection')
        # Keep all sources/native map inspections ahead of persistent C. This
        # pass cannot authorize a later write without the held native ticket.
        transactions=self.resources_inspect(resources['files'])
        self.settings(looks=False)
        if self.config['sound']:
            self.gate_forward();self.sound(prepared)
        self.program_forward();self.resources_apply(transactions);self.settings(looks=True)
        for ticket in resources['files']:
            self.final_checks.append(lambda images,t=ticket:lr.check(t,self.channel.file(t['target_path']),target=True))
        return dict(stage='FEATURE_C_APPLIED_PENDING_POSTREAD_AND_EXIT',complete=False,
            E_F_restored=False,resource_files=len(resources['files']),resource_plan_id=resources['plan_id'],
            master_capsule_sha256=self.master.value['capsule_sha256'])

    def restore_consumers(self):
        """Actual owned consumer C first; resource bytes/EOF are a later stage."""
        fc.need(self.restoring,'Restore needs the authenticated union capsule')
        self.sound(inverse=True);self.gate_restore();self.program_restore();self.settings(looks=True,inverse=True)
        resource=self.child('looks-resource')
        if resource is not None and resource['originals']:
            return dict(stage='RESOURCE_RESTORE_BOUNDARY_REQUIRED',complete=False,union_C_restored=False,
                normal_MSC_required=True,requires_new_boot_evidence=True,
                reason='ORIGINAL_CONSUMER_C_MUST_BE_PROVED_LOADED',automatic_retry=False,
                master_capsule_sha256=self.master.value['capsule_sha256'])
        self.settings(looks=False,inverse=True)
        return dict(stage='FEATURE_C_RESTORED_PENDING_POSTREAD_AND_EXIT',complete=False,
            E_F_restored=False,master_capsule_sha256=self.master.value['capsule_sha256'])

    def resume_resources(self,runtime_factory):
        """Resume with fresh native load proof, never host-invented evidence."""
        fc.need(self.restoring,'Resource resume requires actual union C history')
        original=self.child('looks-resource')
        if original is None or not original['originals']:
            self.settings(looks=False,inverse=True)
            return dict(stage='FEATURE_C_RESTORED_PENDING_POSTREAD_AND_EXIT',complete=False,E_F_restored=False)
        runtime=runtime_factory()
        current={p:self.channel.file(p) for p in original['originals']}
        prefix=rr.restore_resources(current,original,runtime)
        if prefix['phase']=='RESTORE_REFERENCES':
            self.resources_apply(self.resources_inspect(prefix['files']),inverse=True)
        # The helper independently rechecks disk references and the exact
        # original C, including after this session's prefix remaps.
        current={p:self.channel.file(p) for p in original['originals']}
        tail=rr.restore_resources(current,original,runtime_factory())
        for ticket in tail['files']:self._resource_tail(ticket,runtime_factory)
        final={p:self.channel.file(p) for p in original['originals']}
        checked=rr.restore_resources(final,original,runtime_factory())
        fc.need(checked['complete'] is True,'Resource original C/EOF remains pending')
        def check_resources(images):
            for path,row in original['originals'].items():
                raw=self.channel.file(path)
                fc.need(len(raw)==row['eof'],'Final original resource EOF differs')
                for window in row['windows']:
                    at=window['offset'];data=bytes.fromhex(window['hex'])
                    fc.need(raw[at:at+len(data)]==data,'Final original resource C differs')
                rr.references(path,raw,row['eof'])
        self.final_checks.append(check_resources)
        self.settings(looks=False,inverse=True)
        return dict(stage='FEATURE_C_RESTORED_PENDING_POSTREAD_AND_EXIT',complete=False,E_F_restored=False,
            resource_original_C_EOF_verified=True,master_capsule_sha256=self.master.value['capsule_sha256'])

    def _resource_tail(self,ticket,runtime_factory,*,alternative=False):
        folder,build=self._folder('resource-eof');built=rr.build(ticket,build,compiler=self.compiler)
        discard_caches(build)
        _write(folder/'ticket.json',_json(ticket))
        protocol=rr.TailProtocol(ticket);self.protocols.append(protocol)
        action=self.actions_factory(self.channel,folder/'native');self.history.append(action)
        paths=rr.packets(ticket)
        phase_kw={k:paths[k] for k in ('report_bytes','native_report_capacity','native_overhead_units')}
        request=protocol.request(0,os.urandom(16))
        report=action.phase(read_private(Path(built['worker']['path']),65535),paths['request_path'],request,
            paths['report_path'],protocol.accept,**phase_kw)
        if report.get('cleanup_safe') is True and report.get('mapping_state_unknown') is False:
            rr.acknowledge_clean_inspection(action,protocol)
        if report.get('complete') is not True:
            boundary=rr.boundary_from_refusal(report)
            if boundary is not None and not alternative:
                # One explicitly reviewed alternate endpoint is admitted only
                # by the owner's exact parsed-refusal and cleanup contract.
                next_ticket=rr.plan_original_eof_after_clean_refusal(protocol,action,
                    self.channel.file(ticket['target_path']),runtime=runtime_factory())
                return self._resource_tail(next_ticket,runtime_factory,alternative=True)
            if boundary is not None:raise boundary
            raise ValueError('Resource EOF inspect did not prove source C/D and a supported RAM endpoint')
        protocol.confirm_source(self.channel.file(ticket['target_path']))
        request=protocol.request(1,os.urandom(16))
        report=action.phase(read_private(Path(built['worker']['path']),65535),paths['request_path'],request,
            paths['report_path'],protocol.accept,**phase_kw,
            before_dispatch=lambda:self._attempt('looks-resource',ticket,request,inverse=True))
        fc.need(report.get('complete') is True and report.get('mapping_state_unknown') is False,
            'Resource EOF apply outcome unknown; no retry or endpoint change')
        raw=self.channel.file(ticket['target_path']);_write(folder/'after.bin',raw)
        protocol.confirm_readback(raw);protocol.finish();action.clean_packets()
