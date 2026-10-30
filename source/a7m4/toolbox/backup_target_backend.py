"""Explicit native backend for a rebuilt, feature-scoped backup target.

Only native lifecycle/adapters are shared with legacy original recovery. The
preflight authority is independent and re-derives current complement+backup C.
"""
from pathlib import Path
import subprocess

from .original_restore_backend import OriginalRestoreBackend, path_inventory
from .backup_target_execution import ValidatedExecution, authenticated_payload
from .backup_target_program import batches as program_batches
from . import backup_target_sound, backup_target_runtime, sound_scope, looks_program
from . import original_ap_load
from .capture_inputs import read_private
from .native_channel import channel_class
from .run_log import event


class BackupTargetBackend(OriginalRestoreBackend):
    def __init__(self,output,*,authority,**kwargs):
        if type(authority) is not ValidatedExecution:raise ValueError('A new job-local rebuilt authority is required')
        super().__init__(output,**kwargs);self.authority=authority;self.needs_rebuild=False

    def preflight(self, plan):
        self.plan = self.authority.checked_plan(plan)
        if self.plan['blockers']:
            raise ValueError('Backup-target scope has unresolved blockers')
        if not self.compiler:
            raise ValueError('Bundled Zig compiler is unavailable')
        program_batches(self.authority)
        backup_target_runtime.make_probe(self.authority)
        if any(r['kind'] in ('ap','cp') and r['action']!='NO_CHANGE' for r in self.plan['objects']):
            # Establish the finite model ABI and compile its read-only helper
            # locally BEFORE any ST save or physical startup round-trip.
            from . import restore_look_model as model,restore_st_settings as st,settings_archive
            source_settings=settings_archive.load_snapshot(Path(self.plan['scope_plan']['current_capture']['receipt']).parent/'settings')
            for pair in st.PAIRS:st.shape(source_settings,pair)
            ap=next(r for r in self.plan['objects'] if r['kind']=='ap')
            model_plan=model.validate_plan(model.make_plan(read_private(ap['original_path'],160*1024*1024)))
            model.build(model_plan,self.output/'consumer-model-preflight-build',compiler=self.compiler)
        if any(r['kind'] == 'audio' and r['action'] != 'NO_CHANGE' for r in self.plan['objects']):
            images={r:read_private(next(x['source_path'] for x in self.plan['objects'] if x['target_path']==path),160*1024*1024) for r,path in sound_scope.PATHS.items()}
            # The program transaction restores owned cutoff/Gate C first.
            # Check the sound helper against that authenticated next stage;
            # execute() independently rebuilds it from fresh live CP afterward.
            cp=next(row for row in self.plan['objects'] if row['kind']=='cp')
            images['cp']=authenticated_payload(self.authority,cp,target=True)
            backup_target_sound.ticket(self.authority,images)
        for row in self.plan['objects']:
            if row['kind'] != 'resource' or row['action'] == 'NO_CHANGE':
                continue
            target = read_private(row['original_path'], 16 * 1024 * 1024)
            if Path(row['path']).name.startswith('string_'):
                from .looks import _strings
                _strings(target)
            else:
                from ..research.native_icons import _inspect_bank
                _inspect_bank(target)
        self.reads, self.owned, self.reports = path_inventory(self.plan)
        from .feature_job import native_inventory
        scoped_reads,scoped_owned=native_inventory()
        self.reads.update(scoped_reads);self.owned.update(scoped_owned)
        from . import restore_look_model as model
        self.owned.update({model.REQUEST_PATH:model.REQUEST.size,model.RESULT_PATH:model.REPORT.size})
        self.channel_type = channel_class(self.reads, self.owned, readonly_reports=self.reports)
        version = subprocess.run([str(self.compiler), 'version'], capture_output=True, text=True, check=True, timeout=20)
        if version.stdout.strip() != '0.13.0':
            raise ValueError('Zig0.13 is required')
        self.ready = True
        event('backup-target-backend-preflight', status='READY', scope_plan_id=self.plan['scope_plan_id'])

    def __enter__(self):
        # Share only the authenticated lifecycle. Instantiate scoped adapters,
        # never legacy full-file readback or sound atomic execution policies.
        from contextlib import ExitStack
        from types import SimpleNamespace
        from .native_actions import NativeActions
        from .usb_read import ServiceSession
        from .device_job import Journal
        from .settings_channel import SettingsChannel
        from .original_runtime_inventory import OriginalRuntimeInventory
        from .original_wbi import OriginalWBI
        from .backup_target_program import Adapter
        self.stack=ExitStack();self.host_stack=ExitStack()
        try:
            self.host_stack.enter_context(self.lock())
            self.camera_io_started=self.session_factory is None
            self.released=self.release(self.output)
            self.session=(self.session_factory(self.channel_type,self.released) if self.session_factory else
                ServiceSession(channel_factory=self.channel_type,expected_usb_serial=self.released['camera']['usb_serial']))
            self.channel=self.stack.enter_context(self.session)
            for path in (*self.owned,*self.reports,'/tmp/jbusy'):
                if self.channel.peek(path) is not None:raise ValueError('Unowned native state present: '+path)
            self.identity_actions=NativeActions(self.channel,self.output/'identity-native')
            runtime=self.runtime_evidence();self.serial=self.channel.serial()
            self.settings=SettingsChannel(self.channel,intent=Journal(self.output/'settings-wire'),reply=Journal(self.output/'settings-wire-replies'))
            self.inventory=OriginalRuntimeInventory(self.channel,self.output/'runtime-inventory',compiler=self.compiler)
            if not self.inventory.measure()['usr_readonly_verified']:raise ValueError('Initial /usr is not read-only')
            self.program=Adapter(self.authority,self.channel,self.output/'programs',compiler=self.compiler,expected_process_id=runtime['process_id'])
            self.resources=SimpleNamespace(needs_readonly_verification=False)
            self.atomic=SimpleNamespace(needs_usr_readonly_verification=False)
            self.wbi=OriginalWBI(self.channel,self.output/'startup-adoption',compiler=self.compiler,runtime_evidence=self.runtime_evidence)
            return self
        except BaseException:
            self.poison_unknown()
            try:self.stack.__exit__(*__import__('sys').exc_info())
            finally:self.host_stack.close();self.stack=None
            raise

    def prepare_current_runtime(self):
        from .original_restore_job import RequiredBoundary
        runtime=self.runtime_evidence()
        self.source_load=backup_target_runtime.verify(self.authority,self.channel,self.output/'source-ap-runtime',
            compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'],endpoint='source')
        if self.source_load['C_loaded_verified']:return self.source_load
        self.adoption_endpoint='none'
        raise ValueError('Current AP C is not proved loaded; no restore or source adoption dispatched. Preserve the device state and export diagnostics before proceeding.')

    def _original_runtime(self):
        from .original_restore_job import RequiredBoundary
        runtime=self.runtime_evidence()
        if self.original_load is None:
            self.original_load=backup_target_runtime.verify(self.authority,self.channel,self.output/'target-ap-runtime',
                compiler=self.compiler,boot_id=runtime['boot_id'],pid=runtime['process_id'])
        if not self.original_load['C_loaded_verified']:
            raise RequiredBoundary('Backup-target AP C is not yet proved loaded; keep resources and continue after the required startup boundary.')
        if (runtime['process_id'],runtime['boot_id'])!=(self.original_load['process_id'],self.original_load['boot_id']):raise ValueError('Target AP C proof is stale')
        return self.original_load

    def prepare_sound_runtime(self):return self.source_load

    def restore_programs(self,rows,targets):
        result=self.program.execute()
        self.needs_rebuild|=bool(result.get('batches'))
        return result

    def verify_restore_consumers(self,*,prior_boot_id):
        from .original_restore_job import RequiredBoundary
        from . import restore_st_settings as st
        st.require_st(self.settings.capture())
        if prior_boot_id is None:
            # The live current-selection setter ABI is not yet sufficiently
            # established. Keep all patches, rebuild the SOURCE boot snapshot,
            # and prove native models after a physically separate startup.
            self.adoption_endpoint='source';self.needs_rebuild=True
            raise RequiredBoundary('Current look and all six bases are saved as ST. Program patches remain installed. Cold-start, return to MSC, then verify the live ST models before removing patches.')
        from .restore_look_model import verify_after_cold_boot
        ap=next(r for r in self.plan['objects'] if r['kind']=='ap')
        proof=verify_after_cold_boot(self.channel,self.output/'consumer-model',compiler=self.compiler,
            original_ap=read_private(ap['original_path'],160*1024*1024),prior_boot_id=prior_boot_id,
            runtime_evidence=dict(self.runtime_evidence(),fresh=True),snapshot=self.settings.capture())
        st.require_st(self.settings.capture())
        return proof

    def sound_change_required(self):
        ap=next(r for r in self.plan['objects'] if r['kind']=='ap')
        source=read_private(ap['source_path'],160*1024*1024);target=read_private(ap['original_path'],160*1024*1024)
        return sound_scope.words(source)!=sound_scope.words(target)

    def restore_sound(self,row,source,target):
        self.sound_index=getattr(self,'sound_index',0)+1
        runtime=self.runtime_evidence()
        result=backup_target_sound.execute(self.authority,self.channel,self.output/('sound-%03d'%self.sound_index),
            compiler=self.compiler,pid=runtime['process_id'])
        self.needs_rebuild|=not result.get('no_op',False)
        return result

    def inspect_resource(self,row,source,target):
        self._original_runtime()
        return dict(strategy='protected-delta',source_inode_preservation_required=True)

    def _resource_runtime(self):
        proof=self._original_runtime();runtime=self.runtime_evidence()
        return dict(runtime,original_backup_sha256=self.plan['backup_capture']['archive_sha256'],
            load_proof=dict(proof,C_loaded_verified=proof['C_loaded_verified'],fresh=True))

    def restore_resource_prefix(self,row,source,target,inspection):
        from . import backup_target_resources
        self.resource_index+=1
        result=backup_target_resources.restore_prefix(self.authority,row,self.channel,
            self.output/('resource-prefix-%03d'%self.resource_index),compiler=self.compiler,
            pid=self.runtime_evidence()['process_id'])
        return self._resource_closed(row,result,phase='prefix')

    def restore_resource_tail(self,row,source,target):
        from . import backup_target_resources
        from .looks_resource_restore import RequiredBoundary as ScopedBoundary
        from .original_restore_job import RequiredBoundary
        self.resource_index+=1
        try:
            result=backup_target_resources.restore_tail(self.authority,row,self.channel,
                self.output/('resource-eof-%03d'%self.resource_index),compiler=self.compiler,
                runtime_factory=self._resource_runtime)
        except ScopedBoundary as error:raise RequiredBoundary(str(error)) from error
        return self._resource_closed(row,result,phase='eof')

    def _resource_closed(self,row,result,*,phase):
        self.needs_rebuild|=not result.get('no_op',False)
        from hashlib import sha256
        from .native_actions import _write,_json
        if result.get('readback_path'):
            path=Path(result['readback_path'])
            if not path.is_relative_to(self.output):raise ValueError('Resource readback escaped this job')
            raw=read_private(path,16*1024*1024)
            if len(raw)!=result['readback_size'] or sha256(raw).hexdigest()!=result['readback_sha256']:
                raise ValueError('Resource readback evidence changed')
        else:
            raw=self.channel.file(row['target_path'])
            path=self.output/('resource-noop-%03d.bin'%self.resource_index);_write(path,raw)
        self.check_object(row,raw,target=True,expected_size=len(raw))
        record=dict(target_path=row['target_path'],phase=phase,C_D_verified=True,scope_plan_id=self.plan['scope_plan_id'],
            readback_path=str(path),readback_sha256=sha256(raw).hexdigest(),readback_size=len(raw),
            target_eof=row['target']['size'],remaining_tail_sha256=sha256(raw[row['target']['size']:]).hexdigest(),
            backup_archive_sha256=self.plan['backup_capture']['archive_sha256'])
        self.completed_resources=getattr(self,'completed_resources',[])+[record]
        _write(self.output/('resource-checkpoint-%03d.json'%self.resource_index),_json(record))
        from .original_restore_job import RequiredBoundary
        self.resources.needs_readonly_verification=True
        ro=self._try_ro();fresh=self.inventory.measure()
        if not fresh['usr_readonly_verified']:
            if not ro['known_ro_pending'] or ro['final_mount']!=1 or fresh.get('usr_mount_state')!='RW':
                raise ValueError('Scoped resource RO result and fresh mount state differ')
            raise RequiredBoundary('Scoped resource C was read back; /usr remains EBUSY. Close safely, cold-start and continue the selected backup target.')
        self.resources.needs_readonly_verification=False
        return result

    def check_object(self,row,raw,*,target,expected_size=None):
        if type(raw) is not bytes:raise ValueError('Complete current file bytes required')
        side='after_hex' if target else 'before_hex'
        expected=row['target' if target else 'source']
        if len(raw)!=(expected['size'] if expected_size is None else expected_size):raise ValueError('Scoped file EOF differs: '+row['path'])
        if row['kind'] in ('ap','cp'):
            baseline=authenticated_payload(self.authority,row,target=target)
            component=self.plan['scope_plan']['program']['components'][row['kind']]
            for lo,hi in component['owned_ranges']:
                if raw[lo:hi]!=baseline[lo:hi]:raise ValueError('Registered program C differs: '+row['kind'])
            from .backup_target_program import check_dependencies
            # The paired complete images are checked together before WBI;
            # this barrier checks this file's finite D immediately as well.
            check_dependencies([d for d in self.plan['scope_plan']['program']['D'] if d['role']==row['kind']],{row['kind']:raw})
        if row['kind']=='resource':
            from .backup_target_resources import live_dependencies
            live_dependencies(self.authority,row,raw)
            component=next(c for c in self.plan['scope_plan']['resources']['files'] if c['path']==row['target_path'])
            baseline=authenticated_payload(self.authority,row,target=target)
            for lo,hi in component['owned_ranges']:
                hi=min(hi,len(baseline))
                if lo<hi and raw[lo:hi]!=baseline[lo:hi]:raise ValueError('Registered resource C differs: '+row['path'])
            from . import looks_resource_scope
            source=authenticated_payload(self.authority,row,target=False)
            desired=authenticated_payload(self.authority,row,target=True)
            side='after_hex' if target else 'before_hex'
            for anchor in looks_resource_scope._dependencies(row['target_path'],source,desired):
                value=bytes.fromhex(anchor[side]);at=anchor['offset']
                if raw[at:at+len(value)]!=value:raise ValueError('Resource finite D differs: '+row['path'])
        for window in row['windows']:
            value=bytes.fromhex(window[side]);at=window['offset']
            if raw[at:at+len(value)]!=value:raise ValueError('Scoped file C differs: '+row['path'])
        if row['kind']=='audio':
            baseline=authenticated_payload(self.authority,row,target=target)
            if raw[:256]!=baseline[:256] or raw[77504:]!=baseline[77504:]:raise ValueError('Sound C/EOF differs')
        return raw

    def _adopt(self):
        if self.verify_only or self.adoption_endpoint=='none' or not self.needs_rebuild:return None
        if self.wbi_result is not None:return self.wbi_result
        from .native_actions import _write,_json
        for row in self.plan['objects']:
            if row['kind'] in ('ap','cp','audio'):
                self.check_object(row,self.channel.file(row['target_path']),target=self.adoption_endpoint=='target')
        images={r:self.channel.file(p) for r,p in sound_scope.PATHS.items()}
        from .backup_target_program import check_dependencies
        check_dependencies(self.plan['scope_plan']['program']['D'],images)
        self.wbi_result=self.wbi.adopt(program_fullpost_verified=True,approval_verified=True,no_ssh_started=True)
        _write(self.output/'startup-adoption-result.json',_json(dict(endpoint=self.adoption_endpoint,
            validation_scope='registered-backup-C-and-explicit-D',whole_F_hash_admission=False,**self.wbi_result)))
        return self.wbi_result

    def finish_known_context(self):
        proof=super().finish_known_context()
        return dict(proof,resource_checkpoints=getattr(self,'completed_resources',[]))

    def restore_settings(self, plan):
        # Scoped looks and AP55 have explicit C/D checks; E/F are observations.
        from .settings_job import SettingsJob
        from .settings_plan import plan_manifest
        from .device_job import Journal
        from .native_actions import _write, _json
        from . import settings_archive, looks_settings, save_effects
        from .usb_read import body_binding
        if not (looks_settings.active(plan) or plan.kind == 'backup-target-ap55' and plan.save_effects_policy == save_effects.NATIVE51):
            raise ValueError('Finite backup-target settings plan required')
        self.settings_index += 1
        prefix = 'settings-%02d' % self.settings_index
        _write(self.output / (prefix + '-plan.json'), _json(plan_manifest(plan)))
        settings_archive.save_snapshot(self.settings.capture(), self.output / (prefix + '-before'))
        def binding(value):
            runtime = self.runtime_evidence()
            return dict(identity=body_binding(self.channel.serial())['serial_sha256'], boot_id=runtime['boot_id'],
                nonce=value.nonce, model='ILCE-7M4', firmware='6.02', exclusive_owner=True)
        job = SettingsJob(self.settings, bind=binding, journal=Journal(self.output / (prefix + '-journal')),
            forward_observation_only=True)
        job.release(plan, dict(schema='a7m4-toolbox-settings-release/1', plan_id=plan.plan_id,
            identity=plan.identity, boot_id=plan.boot_id, nonce=plan.nonce, backup_verified=True,
            program_dependencies_verified=True, user_risk_confirmation_fresh=True, release_gate='RELEASED'))
        result = job.execute(plan)
        self.needs_rebuild|=result.get('writes',0)>0 or result.get('saves',0)>0
        settings_archive.save_snapshot(job.verified_snapshot, self.output / (prefix + '-after'))
        return dict(result, complete=result['status'] == 'DONE', plan_id=plan.plan_id, saved_groups=result['saved_groups'])
