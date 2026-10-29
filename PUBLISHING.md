# 发布检查

项目署名统一为 shlo，Git 作者和提交者邮箱使用匿名占位地址 shlo@local。
第三方运行时的许可证、版权人、合法来源说明必须保留；它们不是本项目的作者署名。
本项目尚未选择自己的开源许可证，发布工具不会擅自指定 MIT 或其他许可。

每次发布：

1. 运行 `python3 tools/test_release_hygiene.py` 和 `python3 tools/check_release.py --source --history`。
2. 用 `tools/make-release.sh` 构建 macOS、用 `tools/pack-windows-src.sh` 构建 Windows。两者内置检查，命中规则即失败；不要通过删除检测规则来放行产物。
3. 用 `python3 tools/pack-source.py` 导出不含 Git、agent 记忆、缓存的源码包。不要把项目目录整体手工拖到 GitHub。
4. 对要上传的 ZIP 执行 `python3 tools/check_release.py <ZIP路径> ...`。macOS 还要解压验证 `codesign --verify --deep --strict`，然后更新清单体积、SHA256 和 SHA256SUMS-release.txt。
5. 上传最终发布目录。GitHub Actions 会再次检查当前源码、Git 作者历史、历史文件正文与提交说明。CI 必须通过；可在 GitHub 分支保护中将 Release hygiene 设为必需检查。

检查覆盖已定义的残留规则，并非全部原创性或全部传递依赖许可的认证。
工具无法阻止人为绕过脚本直接上传，也无法识别所有未知姓名、所有密钥格式或未登记的第三方代码；引入新组件时应补充许可证清单及检查规则。
旧历史的私有备份和本地工具记忆只能保存在忽略的 build/ 内，不参与发布。


本次首次公开发布采用无旧历史的源码快照：从 `tools/pack-source.py` 导出的源码创建独立仓库；不要直接推送开发目录的旧 Git 历史。新仓库提交作者和提交者使用 shlo / shlo@local。
推送前在公开源码仓库内运行 `python3 tools/check_release.py --source --history --history-content`。该检查会拒绝历史文件和提交说明中的已登记残留；开发仓库保留的旧历史可能不会通过，这是预期结果，不代表当前导出的源码包包含旧历史。
已知私人姓名的检查标记仅存放在本机忽略的 build/private-audit-markers.json 中，不随源码发布。公开检查工具不内置私人姓名原文或摘要；CI 使用通用规则检查，无关对标名称使用摘要匹配。发布前还需在本机用私人标记检查实际产物。


## GitHub 页面文案

仓库首页使用 README.md；首次 Release 正文可使用 RELEASE_NOTES.md。

建议 About 简介：

> 把 Claude 环境检查变成一座可闯关的魔塔：本地体检、网络诊断、按需清理与 macOS 哨兵。

建议 Topics：`claude`、`macos`、`windows`、`privacy`、`diagnostics`、`python`、`swift`。
不要在实际上传应用包之前把源码 ZIP 标为安装包，也不要把尚未完成的 Windows 实机验收写成已支持全部功能。


交流群二维码位于 `docs/assets/community-wechat.png`，由维护者明确授权公开。当前图片标示 11 月 5 日前有效，发布前需确认是否仍有效；失效后替换同名图片，并同步 README 的有效期。
