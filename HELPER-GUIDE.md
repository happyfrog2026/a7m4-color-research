# Helper 指路与 CLI 用法

本资料对应 alpha.62 的共享 driver 快照：**0.5.1-alpha.62**。便捷入口只接受这一匹配版本的已安装 App；发行页面的版本标签不能代替实际 driver 版本检查。

GUI 和 CLI 共用计划、范围校验、任务协调、结果核对及退出逻辑。`source/` 保留源码阅读结构，运行依赖匹配 App 中的完整资源、清单和运行环境。

## 从哪里开始

| 目标 | 入口 | 范围 |
| --- | --- | --- |
| 查看版本与能力 | `./cli/a7m4-toolbox driver status` | 本机历史元数据，不代表当前相机状态 |
| 检查运行依赖及 helper 清单 | `./cli/check-local NEW_DIRECTORY` | 本机，不创建 USB backend |
| 校验便携备份 | `./cli/check-backup ORIGINAL.a7capture` | 本机归档 |
| 导出保留的历史诊断 | `./cli/export-logs NEW_HISTORY.zip` | 当前用户本机记录 |
| 连接检查 | `driver connection-check` | 只读宿主 USB 信息，不打开相机服务 |
| 读取当前状态 | `driver backup` | 显式相机会话 |
| 最终选择封存／规划 | `driver selected-freeze`、`selected-plan` | 本机 |
| 应用最终选择 | `driver selected-install` | 显式相机操作 |
| 从原始备份规划恢复 | `driver backup-target-plan` | 本机 |
| 恢复、续接与启动后核验 | `driver backup-target-restore`、`backup-target-verify` | 显式相机操作 |
| 记录用户最终观察 | `driver backup-target-acceptance` | 核对本机保留证据 |

表中的 `driver …` 都接在 `./cli/a7m4-toolbox` 后面。完整参数以对应命令的 `--help` 为准。

便捷脚本不会自动提权、代填用户确认、重试或跨过恢复节点。App 不在默认位置时，可通过 `A7M4_APP` 指向匹配的 `.app`。GUI 本次打开期间的管理员会话由 App 管理；这些 CLI 脚本不会另建或接管 GUI 会话。

## Helper 阅读地图

| 阅读目标 | 代码入口 |
| --- | --- |
| 共享 CLI、参数与结果 | [cli.py](source/a7m4/toolbox/cli.py)、[run_toolbox.py](source/run_toolbox.py)、[run_research.py](source/run_research.py) |
| 当前备份范围与输入校验 | [resource_profile.py](source/a7m4/resource_profile.py)、[capture_inputs.py](source/a7m4/toolbox/capture_inputs.py) |
| 备份读取与已有数据接纳 | [usb_read.py](source/a7m4/toolbox/usb_read.py)、[capture_recovery.py](source/a7m4/toolbox/capture_recovery.py) |
| 最终选择与素材绑定 | [selected_config.py](source/a7m4/toolbox/selected_config.py)、[selected_plan.py](source/a7m4/toolbox/selected_plan.py) |
| 当前安装主线 | [selected_job.py](source/a7m4/toolbox/selected_job.py)、[selected_stages.py](source/a7m4/toolbox/selected_stages.py) |
| 原始备份与当前状态的恢复计划 | [backup_target_scope.py](source/a7m4/toolbox/backup_target_scope.py)、[backup_target_execution.py](source/a7m4/toolbox/backup_target_execution.py) |
| 恢复阶段、检查点与最终确认 | [backup_target_flow.py](source/a7m4/toolbox/backup_target_flow.py)、[backup_target_job.py](source/a7m4/toolbox/backup_target_job.py)、[backup_target_resume.py](source/a7m4/toolbox/backup_target_resume.py) |
| ST 保护与启动后状态验证 | [restore_st_settings.py](source/a7m4/toolbox/restore_st_settings.py)、[restore_look_model.py](source/a7m4/toolbox/restore_look_model.py) |
| 功能任务与有限请求 | [program_worker.py](source/a7m4/toolbox/program_worker.py)、[resource_worker.py](source/a7m4/toolbox/resource_worker.py)、[native_channel.py](source/a7m4/toolbox/native_channel.py) |
| 声音准备、编码和试听 | [pin_audio.py](source/a7m4/research/pin_audio.py)、[native_audio_codec.py](source/a7m4/research/native_audio_codec.py) |
| 原生图标生成与解码预览 | [native_icons.py](source/a7m4/research/native_icons.py)、[looks_resource_scope.py](source/a7m4/toolbox/looks_resource_scope.py) |
| 临时工作区预算 | [workspace.py](source/a7m4/toolbox/workspace.py)、[native_build.py](source/a7m4/toolbox/native_build.py) |
| 任务互斥与自有临时文件 | [ownership.py](source/a7m4/toolbox/ownership.py)、[job_ownership.py](source/a7m4/toolbox/job_ownership.py) |
| 管理员授权与会话 | [macos_authorization.py](source/a7m4/toolbox/macos_authorization.py)、[macos_session.py](source/a7m4/toolbox/macos_session.py) |
| 分段日志与诊断导出 | [run_log.py](source/a7m4/toolbox/run_log.py)、[diagnostics_archive.py](source/a7m4/toolbox/diagnostics_archive.py) |
| GUI 调用和人工交互 | [A7M4Product.swift](source/packaging/internal-research/A7M4Product.swift) |

源码、许可与来源摘录逐文件记录在 [source-index.json](source-index.json)。摘录保持来源文件内容；其中的历史注释和状态标签不等于当前相机的现场结果。

## 本机准备

### 便携备份与内部收据

`.a7capture` 是便携归档。计划参数 `--capture` 与 `--original-capture` 使用导入／读取后返回的 `capture.private.json` 收据，不能直接用归档替代。

```sh
./cli/check-backup /absolute/path/original.a7capture
./cli/a7m4-toolbox driver portable-import /absolute/path/original.a7capture \
  --output /absolute/path/new-import-directory
```

导入结果的 `receipt` 字段给出后续入口所需的收据。保留导入目录及其绑定材料，不自行改路径或移动进行中的任务目录。

### 封存最终选择

[FL2／FL3＋静音](examples/fl23-silent.draft.json) 和 [M9 上弦组合](examples/m9-recock.draft.json) 是两份 draft 示例。便捷预设填入编辑值；最终执行绑定的是实际编辑值及素材，不是预设编号。

```sh
./cli/a7m4-toolbox driver selected-freeze \
  --draft /absolute/path/fl23-silent.draft.json \
  --original-capture /absolute/path/import/capture.private.json \
  --output /absolute/path/new-selected-config.json

./cli/a7m4-toolbox driver selected-plan \
  --capture /absolute/path/current/capture.private.json \
  --selection /absolute/path/new-selected-config.json \
  --selection-sha256 SELECTION_SHA256_FROM_FREEZE_RESULT \
  --output /absolute/path/new-selected-plan.json
```

`selection_sha256` 取封存结果中的同名字段，不是整个 JSON 文件的摘要。需要声音时另传 `--prepared`，需要自定义1名称图标时另传 `--native-project`；素材参数必须与最终选择相符。

### 声音与图标

```sh
./cli/a7m4-toolbox pin-sound-presets
./cli/a7m4-toolbox pin-sound-prepare --help
./cli/a7m4-toolbox pin-sound-verify --help
./cli/a7m4-toolbox pin-sound-preview --help
./cli/a7m4-toolbox native-icons --help
```

这些是本机素材准备入口，不会安装到相机。试听和图标预览由最终编码结果解码生成。名称及列表普通态、选中态、回放态的图标由同一项目绑定；当前产品部署自定义1，其他槽保持原始状态。

便捷预设采用40 ms上弦间隔与1/8秒分界；最终配置也提供1/50秒候选。曝光分界、KA-SHA内部间隔和上弦间隔分别定义；匹配性仍由完整素材清单检查，不因修改 draft 而自动成立。

## 相机操作与恢复节点

实际相机命令需要明确的本次执行、电量、MSC、备份及风险确认。GUI 提供交互指引；直接用 CLI 时，应先阅读对应 `--help`，按真实观察提供标志。

当前正式安装入口为 `driver selected-install`。从原始备份恢复的主线是：

```text
校验原始备份
→ 读取新鲜当前状态
→ backup-target-plan
→ backup-target-restore
→ 按安全检查点完成用户操作，重新读出并续接
→ backup-target-verify
→ backup-target-acceptance
```

恢复计划依据当前读出与所选原始备份，不要求用户提供原先的安装顺序。它恢复已支持功能范围，不表示所有备份材料或全部个人设置都被覆盖。

需要 ST 保护阶段时，工具先保存当前创意外观及六槽基础外观为 ST，并等待新的启动和实际界面状态证明。第一次重启后，当前外观应为 ST；新增外观选项仍可能出现在菜单中，这不是恢复完成。

每个待续节点都需要该节点之后的新启动、新鲜当前读出、同机身及同原始备份检查；复选框或重新插 USB 不能代替这些事实。CLI 续接使用 `--previous-job` 指向安全检查点，并在实际完成重启后提供 `--startup-confirmed`。每轮使用新输出目录，保留旧任务目录供证据核对。

恢复所需轮数按现场条件决定。用户仅在工具确认本阶段已安全退出并明确提示后执行冷启动：断开USB-C → OFF → 等约15秒；垃圾桶图标旁的红灯若仍亮，继续等到熄灭 → 取出电池 → 等30秒 → 装回开机 → 重新连接并进入MSC。

启动后机读核验通过仍不等于最终完成。用户还需确认名称图标、声音、实际拍摄和回放，随后保存最终检查结果。结果未知或退出未确认时，保留现场并导出诊断，不直接重试。

## 检查范围与记录

当前文件读取范围为11对象，并保留必要设置和身份材料；语言资源限英语、简体中文、繁体中文的横竖两组。旧73对象归档仍可本机核验，设备操作使用当前支持范围。

C 表示本次具体功能范围，D 表示安全处理它所需的依赖。E／F 的无关变化可以记录，不因与旧备份不同而单独阻断；真实的输入结构、必要依赖和退出条件仍须核对。

工作区按实测容量预算，每份上传严格小于65536 B，保留至少8 MiB空间。宿主完整读取与相机端的小包工作区是不同约束。输出盘另建议预留1 GiB日志空间；空间提示不能保证后续保存一定成功。

`export-logs` 应以当前用户运行，不整体套 sudo。stdout 是结构化结果，stderr 是诊断，二者分别保存；进程退出本身不代表相机任务已完成。

源码中的其他历史入口和注释保留供研究，不应当作当前 GUI 的推荐流程。当前公开指路以 `selected-*` 与 `backup-target-*` 为主。
