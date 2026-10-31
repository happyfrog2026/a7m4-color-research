# A7M4 Color Research

[English](README.md) | 简体中文

[Telegram（推荐）](https://t.me/+gmbCDvVseX41Nzcx)
请不要随便下载就用，群里会通知：）
请至少预留20分钟用于应用更改，至少保留35分钟用于恢复备份。
目前版本支持FL2/FL3/M9滤镜USB-C导入，和自定义电子快门声。
本项目抛砖引玉，仅限个人学习用，严禁用于商用。
使用有风险，一切责任由使用者负责。

A7M4 色彩管线与创意外观研究。

本仓库用于发布项目文档及选定的发行资料。

## 研究资料

本次提供 alpha.62 的研究说明、共享 CLI 入口与源码摘录，便于阅读、复核和继续研究。

| 入口 | 内容 |
| --- | --- |
| [高层流程图](docs/architecture_zh.md) | 安装、从备份恢复、人工冷启动及功能检查 |
| [Helper 指路](docs/helper-guide_zh.md) | 模块地图、本机检查、备份校验和共享 CLI 用法 |
| [上游研究来源](docs/upstream-attribution_zh.md) | App「参考与关于」中的研究来源及各自用途 |
| [源码摘录](source/) | 对应版本的共享 helper 与 GUI 调用方 |
| [双语文档维护](docs/documentation_zh.md) | 命名、互链和同步更新规则 |

### 支持范围

- A7M4，受支持的 6.02 构建；实际作业会核对机身和版本。
- FL2／FL3、固定 M9 配方、自定义1的显示名称及图标，以及电子快门声音。
- 从修改前的原始备份恢复已支持功能范围；中间检查点不代表恢复完成。
- 每次重新配置前，先按工具指引从原始备份恢复。

源码摘录用于阅读与继续开发，运行入口复用匹配 App 的完整运行环境。它不是可直接启动的独立安装目录。对应 driver 版本及使用条件见 [Helper 指路](docs/helper-guide_zh.md)。

### 本机 CLI 检查

```sh
./cli/a7m4-toolbox --help
./cli/a7m4-toolbox driver status
./cli/check-local ./new-local-check
./cli/check-backup /absolute/path/original.a7capture
./cli/export-logs /absolute/path/new-history.zip
```

这些示例只检查本机环境、已有备份及本机日志，不打开相机服务。创建输出时使用新目录或新文件名。实际相机操作请按匹配版本 App 的提示进行，保持连接；仅在明确提示冷启动时按步骤断开。

## 许可

本仓库新增文档与便捷入口遵循 [PolyForm Noncommercial License 1.0.0](LICENSE)。已有源码摘录及第三方组件保留其原有许可、版权和必要声明，见 [来源与许可说明](docs/third-party-notices_zh.md)。
