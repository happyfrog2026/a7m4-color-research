# A7 IV 工具箱：来源与许可

本项目免费，用于内部个人学习，不参与收费项目。项目原创代码、界面、
位图字形、合成图标、程序合成音效与新文档适用随附 MIT LICENSE。
这段使用说明不改变任何上游软件或厂商材料的原有许可。

发行元数据中的 `LicenseRef-Internal-Study-Distribution` 描述这一内部组合包，
不是对第三方代码或素材的新授权。根目录 `LICENSE` 仅适用于本项目自有 MIT
代码；其他组件各自适用本文件、逐组件来源清单及随附原文所列的许可和范围。
完整代码包、App 和源码引用均不扩大 Sony、机主素材或上游组件的既有权利。

## 上游研究

- [QAQLeonard/a7c2-fl23-research](https://github.com/QAQLeonard/a7c2-fl23-research)：
  原生滤镜数学、声音与资源架构参考。a7m4/research/lut.py 的数学适配
  保留其完整 MIT 声明于 a7m4/research/data/C2-LICENSE.txt 和
  data/lut-runtime.json。原生图标库格式与 F0 编码亦参考其 verticaltool；
  具体适配和来源由 native_icons.py 及模板清单记录。M4 地址、身份与适配证据单独记录；未附 C2 校准
  模型、上游用户 CUBE、完整固件或原照片。
  0.3.0 的 native_audio_codec.py 移植其 filter0 编解码，保留完整作者 MIT 声明；
  编码后的声音仍保留源素材权利。软件解码不代表精确机内采样率已测量。
- [Liwenru88/a7r5-rea](https://github.com/Liwenru88/a7r5-rea)：
  资源、启动与更新器背景研究。旧仓库中的 Apache-2.0 派生解析器保留其
  原声明，本版普通界面不导入它们。
- [DavidBuchanan314/ILCE-7M4-RE](https://github.com/DavidBuchanan314/ILCE-7M4-RE)：
  M4 启动与救援背景参考；不附其硬件 payload 或未授权源码树。
- [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)：
  Sony 普通 USB 认证及服务驱动子集实际用于显式设备命令，保留完整 MIT；环境检查不枚举设备。来源、逐文件 SHA 和范围见 third_party/pmca/PROVENANCE.json；其 crypto.py 引用的 ajalt/python-sha1 另保留完整 MIT 于 LICENSE.python-sha1.txt。

完整研究来源和证据边界见 docs/internal-research/sources.md。

## 内嵌运行时与依赖

Mac 应用自带原样 CPython 3.12.15，来自 Astral 的
[python-build-standalone](https://github.com/astral-sh/python-build-standalone)。
运行时完整原许可材料保留在 Contents/Resources/runtime-licenses，
Python 的 PSF 与历史声明还在 python/lib/python3.12/LICENSE.txt。
运行时原件与额外依赖分开校验，不以修改原运行时的方式安装依赖。

NumPy／Pillow 使用固定官方 wheel；USB 依赖来自本机已解包、逐份 RECORD 核验的固定缓存，未把缓存重新标成有原始 wheel URL／SHA 的下载件。完整文件、dist-info、RECORD 与原许可保留在
Contents/Resources/vendor，来源及每个文件的 SHA-256 见
vendor/vendor-manifest.json：

- NumPy 2.3.4：NumPy BSD 许可及 wheel 所附完整第三方声明，见
  numpy-2.3.4.dist-info/LICENSE.txt。本次 arm64 wheel 使用系统 Apple
  Accelerate；上游通用许可中提到 OpenBLAS、LAPACK、GCC 等，不表示这些
  二进制库均随本包附带。
- Pillow 12.0.0：MIT-CMU/PIL 及其附带第三方库完整声明，见
  pillow-12.0.0.dist-info/licenses/LICENSE。

源码／wheel 的使用者自行安装这些依赖；Mac 应用已内置。
构建工具 setuptools、wheel、dmgbuild、ds-store、mac-alias、
Apple Swift/AppKit/SwiftUI SDK 不随应用运行时重新分发。
应用未做 Developer ID 签名或公证，只有本地 ad-hoc 完整性封装。
应用额外内嵌完整官方 Zig 0.13.0 macOS arm64 分发，不删减其库与资源；按用户本机源在本地构建受来源约束的 helper，不自动下载。编译器 MIT 与 LLVM／Clang、libc 等完整声明及补充源索引见 packaging/compiler-licenses/zig-0.13.0；App 内对应 zig/distribution-licenses 与 compiler-manifest.json。
源码／wheel 使用者自行提供受版本约束的编译器；App 已包含。

## 声音与图片

data/assets 的 factory-ka.wav、factory-sha.wav、factory-kasha.wav
是从机主提供的本地研究输入解码出的三个短原厂试听片段，按本次明确要求
随内部个人学习应用提供。它们保留 Sony 原有权利，不适用本项目 MIT，
也未取得向公网发布的授权。公开发行前须另行审查并移除或替换。

dry-*、soft-* 为本项目原创程序合成的快门感音效，不是相机录音；
data/assets 中旧预置 PNG 为原创合成图标。各文件来源、权利与完整哈希
见 a7m4/research/data/assets/manifest.json。

0.3.0 的 m9-sha-dry.wav、m9-recock.wav 为机主提供的研究媒体中截取的短片段，
仅供此次内部个人学习使用，不适用项目 MIT，也没有获得公网再分发授权。
M9 预设在本机重新合成；不得将新生成的 20 ms 配对声音称作 R066 已验收原始文件。

0.2.1 的 data/native-icon-templates.json 按本次要求保存少量原生边框、
槽号、右上标记与透明像素模板，不含完整图形库。它们来自机主本地研究输入，
保留 Sony 原有权利，仅供本次内部个人学习，不能因使用本项目生成器而视为
MIT 授权或获准向公网分发。生成图标中的原生框架仍受此边界约束。
英文字体与汉字字体读取 Mac 系统现有文件；字体文件不随应用重新分发。
字形大小、量化和压缩来源记录在每次导出的清单中。PNG 是最终原生压缩数据
解码后的预览，原生数据与完整本地图形库目标不因导出而改变其原有权利。
用户自选声音、图片和字体保留各自权利，不会自动上传。本产品不开放滤镜／CUBE 上传。

本包不附完整厂商固件、图形库、机身备份／校准、原照片、SSH 密钥或凭证。
备份和本地输出由用户保存在自己的环境，不能作为项目开源许可的一部分。

## 0.4 USB、helper 与固定配方

PyUSB 1.3.1 保留 BSD 声明；PyCryptodomeX 3.24.1 保留其原公有领域及 BSD 部分声明；importlib_resources 7.1.0 保留 Apache-2.0。libusb_package 1.0.30.0 及其 libusb 二进制保留各自声明；libusb 按 LGPL-2.1-or-later，完整对应源归档、COPYING 与固定 SHA 位于 dependency-sources/libusb-1.0.30。USB 文件身份以 vendor-manifest.json 及其来源索引为准，不声称已下载并审查不存在的 wrapper sdist。

program-worker、PIN dynamic／rebase／family 等从 C2 事务算法适配的源码保留逐目录 LICENSE.C2／NOTICE 和包内副本。工作区／boot probe、resource atomic worker、产品协调及 GUI 的新作部分适用根 MIT。所有 source-bound helper 在用户本机按完整来源重建，发行物不附带某台机身的 frozen header、生成二进制或完整原件。

FL23 小型程序 delta、3272 B 设置跨度及少量原生指令／位图框架为 Sony-derived 数据，仅供本次内部个人学习，保留原有权利。具体大小、来源和每段 SHA 见各 data 索引；不包含整套固件或机身校准。

固定 M9 表／basis 来自 Ralf Brown 与 darktable contributors 的 Leica M9 style，按 GPL-3.0-or-later 保留来源、变更说明及完整原文。见 a7m4/toolbox/data/m9/PROVENANCE.json、COPYING.txt，以及 looks-r066.json／looks-M9-LICENSE.txt。变更包括省略空间 bilat、pointwise 解释和 C2-response proxy 拟合；不是完整 darktable pipeline，也不声称已测得 M4／Leica 色彩准确度。历史配方的槽位4记录保留作来源；本产品新安装目标为槽位1，其余槽位保持原样。

reference_helpers 是可审阅的历史来源子集。原 helper 可能依赖其原工程与机身绑定文件；清单明确标记 reference-only，不把缺失 private header 的旧 binary 当成产品可复用 helper。产品可执行闭包以发行 helpers／builder／contract 索引为准。


## 原始备份恢复的源码闭包

`a7m4/toolbox/restore_helpers/source/` 保留研究侧 27 文件的来源清单、研究 MIT 原文及继承 A7C2 前缀算法的完整 MIT 声明。`a7m4/toolbox/restore_closure/source/` 保留 16 文件的独立清单、MIT／NOTICE、逐字前向 WBI prepare/drop 源码、RO-only helper 与公开离线 review。生成的用户私有 WBI 头、请求、ELF、真实读回及完整固件不进入发行包。产品桥接与日志新增代码按根 MIT 许可。

独立的原始 EOF 只读证明与尾部恢复 helper 继承上游 tail-restore 的 MIT 条款，分别保留完整原文于 `a7m4/toolbox/data/original-resource-tail-runtime.LICENSE.MIT` 和 `a7m4/toolbox/data/original-resource-tail-original.LICENSE.MIT`。两者使用独立源码及协议；原始 27 文件快照保持不变，生成的机身绑定头、请求及二进制不随包分发。

## 首次声音 C/D helper

新增 sound-scope 从已保留上游声明的 PIN 研究事务适配，独立约束首次声音描述字段、声音库首段、追加尾与 EOF；其余区域仅观察。完整上游 MIT 原文及变更说明见 native/sound-scope/LICENSE.C2、NOTICE.md，和包内 data/sound-scope.LICENSE.C2、sound-scope.NOTICE.md。生成的机身绑定 header、ELF、声音原件与实际作业不进入代码发行包。
