# 凭据与发布范围

GitHub 仓库仅保存源码、离线测试、依赖锁文件和无凭据的配置示例。

以下内容保留在运行机器上,不得提交或附在公开 issue 中:

- 实际 `config.toml`、其他本机配置和 `.env` 文件。
- 登录 token、个人订阅地址、节点地址和密码、账户资料。
- `data/`、日志、生成的 Clash/QX 订阅及备份、临时和恢复副本。
- Agent 记忆、编辑器设置、私钥、凭据容器及打包产物。

## 本机配置

复制 `config.example.toml` 后在本机填写实际 API 地址。示例使用保留域名,不能直接连接真实服务。配置中的相对数据路径以项目根目录为基准。

登录 token 可继续使用 `auto` 从已登录的 macOS App 读取,也可通过 `SUBLOADER_TOKEN` 注入。个人订阅地址可通过 `SUBLOADER_SUBSCRIPTION_URL` 注入。这两个环境变量优先于 TOML,不会写回配置文件。部署平台应使用其 Secret 设置保存实际值。

生成的订阅默认不包含账户邮箱、到期时间和流量,账户信息也不写入日志。原始 JSON 与订阅中的节点密码仍属于私有运行数据,必须限制文件和 HTTP 服务访问权限。

## 提交前检查

```sh
git config core.hooksPath .githooks
git add README.md SECURITY.md pyproject.toml uv.lock run.sh config.example.toml .gitignore .githooks .github core tests scripts
.venv/bin/python scripts/check_release.py
git diff --cached --stat
```

检查器读取 **Git 暂存区中的版本**。除了常见凭据格式和个人路径,在本机存在私有配置/原始 JSON 时,还会在内存中比对其凭据、节点地址与邮箱。报告只含文件位置与问题类别,不回显匹配值。不会读取系统偏好、密钥链或项目外的节点文件。

GitHub Actions 在 push 和 pull request 时运行同一发布检查及离线测试,不需要账户或订阅 Secret。工作流仅请求源码读取权限,第三方 Actions 固定到完整提交 SHA。远端工作流属于后续检测,首次泄露防线仍是本机提交前检查。

`.gitignore` 不能清除已经提交的历史。当前项目从干净 Git 历史开始准备发布;以后若凭据进入提交,应先撤销相关凭据,再清理所有受影响的分支和标签。提交钩子需在每次新克隆后启用,且不能替代对最终提交和历史的人工审查。

不要将整个工作目录打包后上传。GitHub 推送应只发送已检查的 Git 提交,初次推送时使用 GitHub 提供的 noreply 提交邮箱,避免在提交元数据中公开个人邮箱。
