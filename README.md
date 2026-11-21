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

需要 Python 3.11 或更新版本,以及 macOS 或支持 `fcntl.flock` 的 Unix 环境。自动读取 App 登录 token 的功能仅用于 macOS;其他环境可通过环境变量或本机配置提供 token。

使用 uv 安装锁定依赖:

```sh
uv sync --frozen
cp -n config.example.toml config.toml
```

在本机 `config.toml` 的 `api.api_urls` 列表中填写实际 API 根地址,需要时填写域名发现接口。样例中的 API 地址列表为空,至少填写一个地址后才能运行。已有本机配置时保留原文件。

首次配置只需关注两项: `api.api_urls` 填 API 根地址,`api.token` 选择登录方式。示例已选择 `rules.preset = "builtin"`,可以先生成订阅,不需要搭建规则 HTTP 服务。生成文件位于 `data/subscriptions/`。跑通后再按示例中的步骤切换规则来源。

凭据可以使用 `SUBLOADER_TOKEN` 和 `SUBLOADER_SUBSCRIPTION_URL` 环境变量注入,优先于 TOML,不会写回文件。部署平台应使用 Secret 设置保存实际值。文件中的 `token = ""` 或 `token = "auto"` 会从已登录的 macOS WWSS App 偏好设置读取 token。程序不接收账号密码,也不会自动登录或续期 token。

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

全部 27 个配置项及说明均已在 [config.example.toml](config.example.toml) 中显式列出,直接修改对应值即可。

配置文件中,可选字段填写空字符串 `""` 或省略该字段都会使用程序默认值。明确填写的 `false`、`0` 会保留。列表使用 `[]`: `api.cloudapi_urls` 为空时跳过发现,`rules.mirror_urls` 为空时使用默认镜像;必填的 `api.api_urls` 不能为空。`api.subscription_url` 为空时跳过个人订阅规则抓取。环境变量在默认值合并后覆盖配置,因此已设置但为空的 `SUBLOADER_TOKEN` 会报错,不会自动切换到其他凭据来源。

| 配置 | 默认值 | 含义 |
|---|---|---|
| `api.token` | `auto` | 自动读取、环境变量或本机手工配置 |
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
