# 来源与许可说明

本仓库新增文档和便捷入口适用根目录的 [PolyForm Noncommercial License 1.0.0](LICENSE)。已有源码摘录保留各自原许可；根许可证不覆盖或替换第三方许可。

## 已有源码与声明

- `source/LICENSE` 保留原始宿主源码快照的 MIT 许可及版权声明。
- A7C II 相关数学、原生编解码和任务算法保留完整 MIT 声明，见 `source/a7m4/research/data/C2-LICENSE.txt`，以及各 native 目录的 `LICENSE.C2`、`LICENSE.A7C2`、`NOTICE.md` 和包内对应声明。
- 受限 USB 源码子集来自 [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)，保留 `source/third_party/pmca/LICENSE.txt`；其中引用的 ajalt/python-sha1 保留 `LICENSE.python-sha1.txt`。逐文件来源见同目录 `PROVENANCE.json`。
- M9 配方的历史来源为 Ralf Brown 与 darktable contributors 的 Leica M9 style，其来源及 GPL-3.0-or-later 声明保留在源码快照相应许可文件中。此源码摘录不包含配方数据与完整素材。
- `source/THIRD_PARTY_NOTICES.md` 是既有组合包的原始来源记录，保留供来源核对；其中对原组合包内容的描述不表示相应素材或运行时已包含在本仓库。

各来源的完整研究归因见 [UPSTREAM_ATTRIBUTION.md](UPSTREAM_ATTRIBUTION.md)。逐目录原文和源文件内的必要声明均予以保留，不以此项目的许可证重新授权。

## 本仓库内容范围

这里提供文档、CLI 便捷入口与源码摘录。完整 App 运行时、原生素材库、录音素材、机身备份、校准、用户照片、设备绑定及私有任务记录不在该源码摘录范围内。用户自行选择的素材保留各自权利。

Python、NumPy、Pillow、USB 依赖及编译工具的运行环境由匹配 App 或使用者自己的环境提供，本仓库没有重复分发这些完整运行时。相关原声明见对应实际发行物。
