# 高层使用流程 · alpha.62

[English](architecture.md) | 简体中文

本图描述工具的阶段、检查与用户操作，不列具体设备地址或实现点位。

```mermaid
flowchart TD
    GUI["GUI：编辑与用户确认"] --> Driver["共享 CLI driver"]
    CLI["CLI：显式参数"] --> Driver
    Driver --> Prepare["本机素材准备、备份校验与计划"]
    Prepare --> Check["机身、版本、当前状态及必要依赖检查"]
    Check --> Action{"本次操作"}
    Action -->|安装| Install["应用所选滤镜、声音与名称图标"]
    Install --> InstallVerify["核对结果并安全退出"]
    InstallVerify --> InstallUser["用户冷启动与功能检查"]
    InstallUser --> InstallDone["安装完成"]
    Action -->|从备份恢复| Compare["原始备份与当前状态生成恢复计划"]
    Compare --> ST["按需保存 ST 保护状态"]
    ST --> FirstBoot["安全检查点；用户冷启动并重新连接"]
    FirstBoot --> STProof["新启动后核对实际 ST 状态"]
    STProof --> Restore["恢复已支持功能配置"]
    Restore --> Ready{"后续阶段的运行条件允许？"}
    Ready -->|需要用户操作| Checkpoint["保存安全检查点并提示"]
    Checkpoint --> Resume["用户完成操作；重新读出并续接"]
    Resume --> Ready
    Ready -->|允许| Finish["名称图标等收尾及完整结果核对"]
    Finish --> FinalBoot["按提示重启；启动后机读核验"]
    FinalBoot --> User["用户确认名称图标、声音、拍摄、回放"]
    User --> Restored["恢复完成"]
    Driver -.-> Records["本机：原件、计划、检查点与诊断"]
    classDef human fill:#fff0d6,stroke:#b77900;
    class InstallUser,FirstBoot,Resume,FinalBoot,User human;
```

黄色节点需要用户操作。ST 保护及其他节点按现场需要安排，不承诺固定重启次数。检查点是安全续接位置，不是任务完成。

## 安装伪代码

```text
install(final_selection, original_backup):
    bind_final_controls_and_exact_assets()
    plan_locally()
    verify_supported_body_version_and_required_dependencies()
    verify_current_baseline_and_workspace_budget()
    retain_required_original_materials()
    apply_selected_configuration()
    verify_each_result_and_final_state()
    clean_owned_temporary_files_and_exit_safely()
    wait_for_user_cold_start_and_feature_checks()
    mark_installation_complete()
```

## 从备份恢复伪代码

```text
restore(original_backup, optional_checkpoint):
    current = capture_fresh_current_state()
    plan = compare_supported_scope(current, original_backup)
    verify_identity_dependencies_and_checkpoint_if_present()

    if ST_protection_is_required:
        save_current_look_and_all_custom_base_looks_as_ST()
        save_safe_checkpoint_and_exit()
        wait_for_fresh_boot_and_current_capture()
        verify_actual_live_ST_state()

    restore_supported_configuration(plan)
    for each_remaining_stage:
        check_current_runtime_conditions()
        if a_user_startup_boundary_is_required:
            save_safe_checkpoint_and_exit()
            wait_for_user_operation_and_fresh_capture()
            rebuild_remaining_plan()
        complete_supported_stage()

    verify_final_results_and_exit_safely()
    verify_fresh_post_startup_state()
    wait_for_user_names_sound_shooting_and_playback_checks()
    validate_retained_evidence_and_mark_complete()
```

恢复依据是所选原始备份与当前状态，不依赖先前安装顺序。恢复范围为工具支持的功能及必要关联项，无关当前数据保持原样。
