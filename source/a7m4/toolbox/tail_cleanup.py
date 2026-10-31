"""Local software status for the integrated original-backup restore workflow.

Portable helper source/contracts are pinned; explicit execution is separate.
This module deliberately imports no channel, USB backend or native executor.
File presence cannot promote the integration to device-ready.
"""
from __future__ import annotations


def integration_status() -> dict:
    return {
        'schema': 'a7m4-toolbox-tail-cleanup-status/1',
        'status': 'INTEGRATED_EXPLICIT_ORIGINAL_RESTORE',
        'camera_io': False,
        'network_io': False,
        'device_ready': False,
        'execution_available': True,
        'device_validation': 'NOT_PERFORMED',
        'recorded_research_validation': 'R067 scoped single-body full-file restoration accepted',
        'historical_acceptance_is_not_product_validation': True,
        'planned_resource_scope': 'existing 70 UXC paths; exact owned append tails only',
        'prerequisites': [
            'verified earliest original backup and complete current same-body capture',
            'resource reference/load evidence and conditional boot barrier if actually required',
            'source equals original full prefix plus independently reconstructed owned append tail',
            'reviewed portable helper builder/parser and fresh native identity/alias inspection',
        ],
        'completion_states': [
            'functional_restore_complete', 'full_file_restore_complete',
            'post_boot_full_file_verification_complete',
        ],
        'automatic_tail_cleanup': False,
        'automatic_retry': False,
        'nor_writes': False,
        'helper_wbi_writes': False,
        'wbi_coordination_contract': 'FORWARD_PREPARE_DROP_V2',
        'reason': '原始备份恢复执行链已接通；本状态查询不检测相机。真实写入须显式执行、完整来源与每次风险确认，新版仍未实机验收。',
    }
