"""One selected installation, retaining the reviewed shared service lifecycle."""
from pathlib import Path
import tempfile
from . import selected_config, selected_baseline, selected_plan, feature_job
from .selected_stages import Stages


def execute(capture_path,selection_path,output,*,selection_sha256,**kwargs):
    import re
    if type(selection_sha256) is not str or re.fullmatch('[0-9a-f]{64}',selection_sha256) is None:
        raise ValueError('Exact confirmed selection SHA-256 required')
    selection=selected_config.load(selection_path)
    if selection['selection_sha256']!=selection_sha256:raise ValueError('Final selection differs from the risk-confirmed snapshot')
    # Baseline targets are transient read-only planning input, not recovery
    # originals. Durable source/backup captures and every native ticket, loaded
    # proof, dispatch ledger and post-readback remain in the owned job output.
    # Keep elevated scratch outside the user workspace and remove it on all
    # outcomes; result_owner need only return its existing capture subtree.
    with tempfile.TemporaryDirectory(prefix='a7m4-selected-baseline-',dir='/private/tmp') as scratch:
        baseline=selected_baseline.prepare(capture_path,selection['original_capture']['path'],Path(scratch)/'targets')
        forecast=selected_plan.make_plan(capture_path,selection,baseline=baseline)
        if selected_config.load(selection_path)!=selection:raise ValueError('Selected configuration changed during local preflight')
        runtime_selection=dict(forecast,selection=selection,selection_sha256=selection['selection_sha256'],expected_selection_sha256=selection_sha256)
        def stages(*args,**kw):return Stages(*args,**kw,selection=selection,baseline=baseline)
        return feature_job._execute(capture_path,output,selection=runtime_selection,
            native_project=selection['display_ref']['path'] if selection['display_ref'] else None,
            prepared=selection['prepared_ref']['path'] if selection['prepared_ref'] else None,
            _stages_factory=stages,_operation_feature='selected-feature-install',**kwargs)
