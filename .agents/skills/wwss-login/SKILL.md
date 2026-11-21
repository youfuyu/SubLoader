---
name: wwss-login
description: "Log in to WWSS using SubLoader's local account configuration, visually read its image CAPTCHA, and save the issued token. Use when the user asks an agent to complete or refresh this login."
---

# 西部世界登录

通过项目内的 `core/login.py` 登录。Python 读取本地账号密码、持有会话 Cookie、提交登录并保存 token；agent 只识别图片验证码并回填答案。不需要额外 OCR 服务或 API key。

这项 Skill 需要能保持标准输入连接的进程执行工具、向该进程写入的工具以及读取本地图片的视觉工具。当前 Codex 中可使用 `exec_command`、`write_stdin`、`view_image`。仅在用户请求实际登录时执行流程；讲解或修改登录实现时无需访问真实账户。

## 执行

1. 在 SubLoader 项目根目录启动 `./run.sh login --agent`，使用持续交互的终端会话（`exec_command` 的 `tty=true`）。用户指定登录配置时追加 `-c`。保留返回的进程 `session_id`，等候 JSON 行事件。此模式不会打开浏览器，也不会提示输入账号密码。
2. 遇到 `captcha_required` 时，用本地图片工具打开事件中的绝对 `image_path`。图片位于该进程持有的临时目录；进程结束后会删除。不要重启命令或在另一个 HTTP 客户端获取验证码，否则会丢失对应 Cookie。
3. 直接识别图片里的验证码字符，保留大小写。看不清时不要猜测：取消当前进程并说明需要人工识别。没有可用的图片工具时同样停止。
4. 用 `write_stdin` 把识别出的字符和一个换行写入同一个 `session_id`。这里的 stdin 只接受验证码，不要把邮箱、密码、token 或 JSON 写进去。
5. 继续读取进程输出，直到完成。`captcha_verified` 仅表示前置验证成功；需要同时看到 `login_succeeded` 和退出码 `0`，才能报告登录完成。成功事件只提供 token 文件路径和权限，token 值不会进入输出。

成功后报告 token 已更新及保存位置。只有用户还要求获取节点时，才继续运行 `./run.sh --once`；该命令通过节点配置的 `api.token_file` 读取文件。

## 失败处理与凭据

- `login_failed` 的 `stage` 区分 `configuration`、`prepare`、`captcha`、`login` 和 `save_token`，`message` 已脱敏。按实际阶段报告失败，保留原 token，不循环尝试登录。
- 账号密码从 `login.local.toml` 或环境变量加载。配置缺失时，请用户在本机补齐；不要 `cat` 私有配置、读取并回显密码，或要求用户把密码发送到聊天中。
- 遇到极验、滑块、额外站点验证或无法识别的页面时，停止并让用户在官方网页完成验证。此流程仅实现图片验证码。
- 不回显、上传或提交 token 文件、私有配置和 Cookie。成功确认以退出码和事件为准，无需把 token 读入模型上下文。
