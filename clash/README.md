# Clash 三份 YAML 文件独立维护

| 文件 | 内容 | 更新方式 |
|---|---|---|
| `WestWorldVPN-clash.yaml` | 只包含 `proxies` 的节点订阅 | 程序下载节点后生成 |
| [groups.yaml](groups.yaml) | 代理组、地区筛选正则、测速参数 | 独立修改分组扩展配置 |
| [routing.yaml](routing.yaml) | 分流顺序、规则源、缓存路径和更新周期 | 独立修改分流扩展配置 |

节点订阅位于 `config.toml` 的 `data.output_dir` 中。三份文件使用纯 YAML,无需 JavaScript。节点订阅不包含 `proxy-groups`、`rules`、`rule-providers`、端口或运行模式。QX 继续输出独立的节点引用文件。

## 在 Clash Verge Rev 安装

1. 导入节点订阅,名称可自行设置。本机链接为 `http://127.0.0.1:8000/pages/subscriptions/WestWorldVPN-clash.yaml`,使用其他服务地址时再调整。
2. 将 `groups.yaml` 保存到 **全局扩展配置（YAML）**。
3. 右键当前使用的节点订阅,打开 **扩展配置（YAML）**,填入 `routing.yaml` 的内容并保存。
4. 两份配置启用后,更新并选中该节点订阅。代理页排序可按使用习惯设置。

使用“扩展配置”入口。加载顺序:节点订阅 → 全局分组配置 → 订阅分流配置 → Mihomo。节点文件只提供节点,启用前需要安装两份配置。

如果已填入之前的 JavaScript 版本,请停用旧的分组和分流脚本,让 YAML 配置生效。

全局和订阅扩展配置按字段覆写或合并;分组文件只写 `proxy-groups`,分流文件只写 `rules` 和 `rule-providers`。参见 [Clash Verge 官方文档](https://www.clashverge.dev/guide/extend.html)。

节点只由 Clash Verge 的当前订阅提供。`groups.yaml` 使用 `include-all-proxies` 引入节点,不配置 `proxy-providers`、订阅地址或额外下载周期,无需匹配订阅名称。更新并重新应用节点订阅后,各组会重新筛选节点。只有空的本地基础配置无法提供节点。

上面的 `127.0.0.1` 指向运行 Clash Verge 的电脑自身,适合 HTTP 服务和客户端在同一台电脑的情况;跨设备使用时改为 HTTP 服务器可访问的局域网地址。含凭据的真实地址只保存在客户端或本机私有副本中。

## 分组配置

```text
节点选择
├─ 自动选择
│  ├─ 自动选择[HK]
│  ├─ 自动选择[JP]
│  ├─ 自动选择[TW]
│  └─ 自动选择[US]
└─ 手动选择（全部节点）
```

与 QX 的对应关系:

| QX | Clash / Mihomo |
|---|---|
| `static` | `type: select` |
| `url-latency-benchmark` | `type: url-test` |
| `server-tag-regex` | `include-all-proxies` 引入节点,配合 `filter` |
| `check-interval=600` | `interval: 600` |
| `tolerance=100` | `tolerance: 100` |
| `alive-checking=false` | `lazy: true` |

例如香港组通过以下字段筛选,无需逐个列出节点:

```yaml
include-all-proxies: true
filter: '(?i)(^|[^a-z])HK([^a-z]|$)'
```

沿用 QX 方案中的 HK、JP、TW、US 国家码,忽略大小写,增加字母边界以减少误匹配。`HK0`、`日本JP · 台湾隧道2`、`TW2` 可以按对应国家码入组;没有国家码、仅包含中文地区名的节点仍保留在手动选择中。“台湾隧道”本身不会让日本 JP 节点进入 TW 组。名称筛选不核验实际出口地区或服务解锁情况。

地区分组固定保留,不匹配任何节点时使用 `empty-fallback: REJECT`,不会自动改为其他地区。此时可改选有节点的地区或手动选择。节点订阅更新并重新应用后,各组会自动引入新节点并重新筛选。测速地址、600 秒间隔、100 毫秒容差和 `lazy: true` 直接在相应地区组中调整。

生成的节点文件仍按地区优先级排列,各地区内直接按完整名称的字符串升序比较,如 A117 在 A83 前。`include-all-proxies` 引入节点时由内核按名称排序,客户端也可以调整显示顺序;代理组内不要求保留节点文件的地区顺序。

节点更新周期在 Clash Verge 的订阅设置中管理,与地区组的 600 秒测速间隔相互独立。外层“自动选择”是手动选择地区的 `select` 组,选定地区后,其 `url-test` 子组才负责自动选择节点。

字段说明见 [Mihomo 代理组文档](https://wiki.metacubex.one/config/proxy-groups/)。QX 的 `.system` 图标名称不用于 Clash。

## 分流配置

`routing.yaml` 维护 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) 的 private、reject、direct、proxy、cncidr 五组规则,以及局域网 IP 直连和最终 `MATCH,节点选择` 兜底。

规则源、86400 秒更新周期和 `./ruleset/` 缓存路径在各 `rule-providers` 项中配置。规则文件由 Mihomo 下载和缓存,缓存相对于内核工作目录,无需项目提供 HTTP 规则服务。

`RULE-SET,private,DIRECT` 位于广告拦截之前,优先直连 `.local`、`.lan`、`localhost`、`home.arpa` 及规则集收录的路由器管理域名。该规则直接匹配域名,补充下方 `no-resolve` 局域网 IP 规则不会主动解析域名的行为。规则集内容见 [private.txt](https://github.com/Loyalsoldier/clash-rules/blob/release/private.txt)。

局域网直连使用一条 `GEOIP,lan,DIRECT,no-resolve`,由 Mihomo 内置判断本机回环、私有地址、链路本地地址等 IPv4/IPv6 地址,不需要逐个展开 `IP-CIDR` 规则或额外下载 GeoIP 数据。保留这条规则可避免路由器、NAS 和本地服务的 IP 请求落入最终代理兜底;`no-resolve` 不会为匹配此规则主动解析域名。参见 [Mihomo 实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/rules/common/geoip.go)。

`RULE-SET,cncidr,DIRECT` 是另一条规则,负责中国大陆 IP 直连,与局域网地址不同,默认保留。

两份配置通过 `节点选择` 这个名称衔接;修改该组名时,需同步调整分流配置中的目标策略名。

## 后续维护

- 更新节点:更新并重新应用当前节点订阅,分组筛选自动生效。
- 修改分组:编辑 `groups.yaml`,将更新后的内容保存到全局扩展配置,重新应用订阅。
- 修改分流:编辑 `routing.yaml`,将更新后的内容保存到订阅扩展配置,重新应用订阅。

配置文件与 Clash Verge 编辑器各自保存内容,修改项目里的文件后需同步保存到对应扩展入口。修改分组或分流配置不需要重新抓取节点。

## 代理页提示“未获取到代理信息”

只导入节点订阅、尚未保存分组扩展时,Clash Verge 可以读到节点,但代理页没有可展示的代理组。将文件放在项目目录中不会自动安装到客户端。

按上面的步骤分别保存全局分组扩展和当前订阅的分流扩展,然后重新应用订阅。可在订阅页点击“查看运行时订阅”,确认最终配置包含 `proxies`、`proxy-groups`、`rules` 和 `rule-providers`。三份源文件仍独立维护,不需要把分组或分流重新写入节点订阅。
