# SubLoader

基于 Python 的 WWSS 兼容订阅下载与转换工具,输出 Clash Verge / Mihomo 配置及 Quantumult X 节点文件。

仓库只包含源码、离线测试、依赖锁文件和无凭据的配置示例。实际服务域名、登录 token、个人订阅链接和运行数据保存在使用者本机。

## 功能

- 通过可配置的域名发现接口和备用 API 获取节点,支持 Trojan 与基础 Shadowsocks 节点。
- 校验节点、稳定按地区排序,处理重名和代理组名称冲突。
- 输出 Clash 的 PROXY/AUTO 分组及 QX 节点引用文件。
- 分流规则按 GitHub 规则集、订阅规则、内置规则逐级降级。
- 校验通过后提交原始 JSON 与两份订阅,写入异常时回滚,并保留最近一次备份。
- 认证重定向保护、独立规则 TLS 校验、响应大小限制及严格 UTF-8 解码。
- 跨配置写入互斥,以及不访问外部网络的回归测试。

## 环境与安装

需要 Python 3.11 或更新版本,以及 macOS 或支持 `fcntl.flock` 的 Unix 环境。自动读取 App 登录 token 的功能仅用于 macOS;其他环境可通过 token 文件、环境变量或本机配置提供 token。

使用 uv 安装锁定依赖:

```sh
uv sync --frozen
cp -n config.example.toml config.toml
```

在本机 `config.toml` 的 `api.api_urls` 列表中填写实际 API 根地址,需要时填写域名发现接口。样例中的 API 地址列表为空,至少填写一个地址后才能运行。已有本机配置时保留原文件。

首次配置时,`api.api_urls` 填 API 根地址;使用账号密码登录时,设置 `api.token_file = "data/wwss-token.txt"`,先按下文登录生成文件。已有 token 可填 `api.token`;使用已登录的 macOS App 时,保持 `api.token = "auto"` 并留空 `api.token_file`。示例已选择 `rules.preset = "builtin"`,生成文件位于 `data/subscriptions/`。

凭据可以使用 `SUBLOADER_TOKEN` 和 `SUBLOADER_SUBSCRIPTION_URL` 环境变量注入,优先于 TOML,不会写回文件。部署平台应使用 Secret 设置保存实际值。`token = ""` 或 `token = "auto"` 时,优先读取配置的 `token_file`,未配置文件才读取已登录的 macOS App。显式 token（包括环境变量）优先于 token 文件。节点下载不会自动登录或续期 token;密码登录由 `core/login.py` 提供,与分流规则下载一样通过核心命令运行。

## 登录获取 token

登录配置使用独立的本地文件。复制示例后填写 `[login]` 中的 `portal`、`email`、`password` 和 `token_file`:

```sh
cp -n login.example.toml login.local.toml
chmod 600 login.local.toml
./run.sh login
```

`portal` 填 HTTPS 门户根地址,它可能与节点 API 地址不同。`token_file` 支持绝对路径和 `~/`;相对路径以登录配置文件所在目录为基准。默认读取项目根目录的 `login.local.toml`,该文件已被 Git 忽略。还可以指定另一份本地配置:

```sh
./run.sh login -c /path/to/login.local.toml
```

配置中填好账号密码后,运行时只需输入图片验证码。`open_captcha = true` 会用默认浏览器打开本地验证码图片;设置为 `false` 时自行打开终端显示的图片路径。整个流程共享会话 Cookie,图片在脚本结束时删除。网页初始化数据在 Python 中解码,不会执行网页 JavaScript。

登录成功后,token 原子保存到登录配置中的 `token_file`（默认 `data/wwss-token.txt`）,文件权限为 `0600`,不会打印到终端。在节点下载使用的 `config.toml` 中配置同一个文件:

```toml
[api]
token = "auto"
token_file = "data/wwss-token.txt"
```

`api.token_file` 的相对路径以项目根目录为基准。登录配置的相对路径以该配置所在目录为基准;自定义登录配置放到其他目录时,可在两份配置里使用同一个绝对路径。配置了文件后,缺失、读取失败或内容无效会报错,不会回退 macOS App。文件内容为单行 token,允许末尾换行。随后直接运行节点下载:

```sh
./run.sh --once
```

命令行参数优先于环境变量,环境变量优先于本地配置。可用 `--email` 或 `SUBLOADER_EMAIL` 覆盖邮箱,用 `SUBLOADER_PASSWORD` 覆盖密码;空环境变量会报错。配置未填写邮箱或密码时才会交互输入,密码不回显。`--portal`、`--output`、`--open-captcha`/`--no-open-captcha`、`--remember-days` 和 `--timeout` 可覆盖对应配置;命令行 `--output` 的相对路径以调用目录为基准。记住登录天数仅支持 `0` 和 `30`（默认）,不代表已确认 token 的有效期。

登录功能位于 `core/login.py`,也可用 `python3 -m core login` 或 `python3 -m core.login` 运行,支持相同配置和参数。`run.sh` 统一调用 `python -m core`,登录凭据仍保存在独立的本地配置中。所有远程登录请求校验 HTTPS 证书,登录 POST 不跟随重定向。登录模块直连网络,与节点下载程序一致。

当前实现依据已分析的网页登录协议,已通过本地模拟接口测试及一次真实账号的 agent 图片验证码登录验证。默认交互模式需人工输入图片验证码,也可由下述 agent Skill 识别并回填;若站点开启极验、额外风控或修改页面协议,脚本会提示失败,需在官方网页登录完成验证。失败时不会自动重试密码或创建账户,也不会更新已有 token 文件。

### 由 agent 识别验证码

项目提供 `.agents/skills/wwss-login/SKILL.md`,可在支持本地读图和交互终端的 Codex 中使用:

```text
使用 $wwss-login，根据本地配置识别图片验证码，完成登录并保存 token。
```

若当前聊天尚未发现该 Skill,可以明确要求 agent 阅读上述 `SKILL.md` 后执行。账号密码仍由 Python 从本机配置加载,不需要发到聊天中。

Skill 调用 `./run.sh login --agent`:登录模块输出 `captcha_required` JSON 行事件和图片绝对路径,然后从同一进程的 stdin 等待一行验证码。agent 打开该图片、识别字符并回填;同一 Python 进程继续使用会话 Cookie 提交验证和密码登录。成功后输出 `captcha_verified`、`login_succeeded` 事件并以 `0` 退出,token 本身不会进入输出。

`--agent` 是供 agent 交互的接口,命令本身不包含 OCR 模型。此模式不打开浏览器,要求账号密码已在本地配置或环境变量中提供。失败时输出 `login_failed` 和失败阶段,不会循环尝试。图片识别不保证成功;无法辨认、极验或滑块验证仍需人工完成。

## 使用

```sh
# 执行一次完整更新,失败按配置重试
./run.sh

# 不重试
./run.sh --once

# 指定配置;-c 也可以位于子命令之后
./run.sh run -c /path/to/config.toml --once

# 强制下载/更新规则缓存
./run.sh rules

# 使用本地账号密码配置登录并保存 token
./run.sh login
```

没有 uv 时,也可以在已有虚拟环境安装 PyYAML 后使用 `python -m core`。相对 `-c` 路径以调用目录为基准,配置中的相对数据路径以项目根为基准。

默认输出:

- `data/latest-wwss-nodes.json`:原始节点与可选账户数据。
- `data/subscriptions/WestWorldVPN-clash.yaml`:完整 Clash 配置。
- `data/subscriptions/WestWorldVPN-quantumultx.txt`:QX 节点引用文件。
- `data/rules/`:规则缓存。
- `logs/subloader.log`:运行日志,2 MiB × 3 份轮转备份。

这些都是本机运行数据,已从 Git 提交范围排除。生成的订阅默认不包含账户邮箱、到期时间和流量,但节点密码仍是必要的私有数据。

## 分流与 HTTP 服务

`rules.preset` 支持:

| 模式 | 行为 |
|---|---|
| `github` | 下载四类规则集,通过 rule-providers 引用发布 URL;不可用时降级 |
| `subscription` | 从本机配置或环境变量提供的 Clash 订阅提取规则;无效时降级 |
| `builtin` | 局域网/国内直连,其他走代理 |

规则源使用 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules),默认通过配置中的镜像下载。规则缓存过期时重新下载,下载失败只复用有效旧缓存。

SubLoader 本身不启动 Web 服务。使用 GitHub 模式时,需要把 `rules.output_dir` 交给现有静态 HTTP 服务,并设置对应的 `rules.provider_base_url`。与其他订阅服务集成时,同时调整订阅输出目录和规则目录。

生成配置前会检查发布端是否提供四份有效规则。服务未启动、路径不匹配或内容无效时,即使本地缓存存在也会降级。客户端仍须能访问配置中的 URL;远程设备的回环地址不会指向下载器所在机器。

订阅模式支持可独立转换的常见规则。复杂逻辑、子规则、平台相关规则或不兼容的正则会整组降级。引用外部 rule-providers 的 RULE-SET 会跳过。

## 主要配置

全部 28 个配置项及说明均已在 [config.example.toml](config.example.toml) 中显式列出,直接修改对应值即可。

配置文件中,可选字段填写空字符串 `""` 或省略该字段都会使用程序默认值。明确填写的 `false`、`0` 会保留。列表使用 `[]`: `api.cloudapi_urls` 为空时跳过发现,`rules.mirror_urls` 为空时使用默认镜像;必填的 `api.api_urls` 不能为空。`api.subscription_url` 为空时跳过个人订阅规则抓取。环境变量在默认值合并后覆盖配置,因此已设置但为空的 `SUBLOADER_TOKEN` 会报错,不会自动切换到其他凭据来源。

| 配置 | 默认值 | 含义 |
|---|---|---|
| `api.token` | `auto` | 显式 token 优先;auto 时读取 token 文件或 macOS App |
| `api.token_file` | 空字符串 | 可选单行 token 文件,相对路径以项目根目录为基准 |
| `api.api_urls` | 样例为空列表 | 必须填写至少一个实际 API 根地址 |
| `api.cloudapi_urls` | 空列表 | 可选域名发现接口 |
| `api.subscription_url` | 空字符串 | 私有 Clash 订阅地址,用于规则降级源 |
| `api.tls_verify` | `false` | 私有 API 的兼容设置,可按服务端证书情况开启 |
| `api.request_timeout` | `15` | 单个请求共享的下载期限,0.001–300 秒 |
| `api.max_response_bytes` | `16777216` | 响应体上限,最大 64 MiB |
| `rules.tls_verify` | `true` | 公共规则和发布服务独立校验证书 |
| `rules.refresh_days` | `7` | 缓存刷新周期,0–3650 天 |
| `output.backup_old` | `true` | 保存订阅旧版本为 `.bak` |
| `output.include_account_info` | `false` | 是否把账户资料放入生成的订阅头 |
| `output.tls_verify` | `false` | 生成的 Trojan 节点是否校验证书 |
| `schedule.max_attempts` | `3` | 单次触发的尝试次数,1–20 |
| `schedule.retry_interval_minutes` | `5` | 重试间隔,0–1440 分钟 |

`api.retry_per_url` 范围为 0–10。请求的连接、TLS、响应头/体与重定向共享期限;系统 DNS 解析阻塞仍由操作系统控制。

显式配置不存在、格式错误、字段无效或路径冲突时以退出码 `2` 结束。路径检查覆盖配置、原始文件、订阅及备份、规则缓存、日志及轮转文件、锁文件和目录,并保守拒绝大小写或 Unicode 正规形式别名。

## 定时与可靠性

程序按次执行,不内置常驻调度器。可使用操作系统调度器或外部任务平台触发,失败重试由 `[schedule]` 控制。执行时应使用能访问配置中服务的网络出口。

执行全程持有运行锁,规则更新单独加锁。提交时按固定顺序获取各写入目录的 `.subloader-write.lock`,不同配置共享输出目录时也不能交叉提交。

自检包含节点类型、数量、名称、地址、端口、加密方法、规则参数/CIDR、代理组和规则提供器引用,以及 Clash/QX 地址、密码、名称和 TLS 参数的一致性。密码不会被裁剪或强制转换,无法无损表示的节点会跳过。

可捕获的写入异常会回滚。多文件替换不保证断电或强制终止时的版本一致;回滚失败会保留 `.rollback` 恢复副本并记录位置。

## 开发与发布

```sh
.venv/bin/python -m unittest discover -s tests -v

git config core.hooksPath .githooks
# 按 SECURITY.md 中的源码清单暂存后执行
.venv/bin/python scripts/check_release.py
```

测试只使用合成节点、临时文件和回环 HTTP/TLS 服务。安装了 Mihomo 或 macOS Clash Verge 时额外执行内核兼容测试;本地 TLS 测试需要 OpenSSL,缺失时明确跳过。

发布检查针对 Git 暂存区,阻止本机配置、运行数据、Agent 记忆、个人路径和常见凭据进入提交,报告不回显敏感值。GitHub Actions 会在 Python 3.11、3.12、3.13 上执行相同检查与离线测试,不需要实际账户凭据。请阅读 [SECURITY.md](SECURITY.md) 中的完整发布范围和提交元数据说明。
