# agh-rules-cn — 面向中文网络环境的业务感知 AdGuard Home 规则集

> 电商、支付、流媒体、AI 的业务链路**零误伤**；纯追踪与垃圾广告**强制拦截**。
> 与社区列表的根本差异不在"拦得多"，而在**能表达意图**。

[![拦截规则](https://img.shields.io/badge/block-113-blue)](rules.txt)
[![放行规则](https://img.shields.io/badge/allow-13-green)](user_rules.yaml)
[![语法](https://img.shields.io/badge/syntax-AdGuard%20Adblock-green)](rules.txt)
[![CI](https://img.shields.io/badge/CI-validate--passing-brightgreen)](.github/workflows/validate.yml)

---

## 一、为什么不用社区列表

社区列表（hagezi / AdGuard / Steven Black / ShadowWhisperer 等）质量很高，本项目把它们**全部作为底座保留**。但它们是**扁平的"发现即拉黑"集合**，存在三个结构性短板。

### 1. 无法表达"同主域下，广告子域要拦、功能子域要放行"

这是中文网络环境最常见的场景。实测社区列表拦截的业务子域共 **427 个**，其中相当一部分是功能必需：

| 业务域 | 被社区拦截的子域示例 | 性质 |
|---|---|---|
| `stripe.com` | `r.stripe.com` / `m.stripe.com` / `q.stripe.com` | **支付回调与 SDK，必需** |
| `facebook.com` | `tr.facebook.com` / `an.facebook.com` | **登录追踪，必需** |
| `tiktok.com` | `mcs.us.tiktok.com` / `mcs-ttp2.tiktokv.com` | **内容分发，必需** |
| `shopify.com` | `v.shopify.com` / `gtm.shopify.com` | **店铺脚本，必需** |
| `paypal.com` | `data.account.paypal.com` / `data.messaging.paypal.com` | **账户数据，必需** |
| `github.com` | `collector.github.com` | **遥测，非必需** |
| `openai.com` | `bzr.openai.com` / `bzrcdn.openai.com` | **CDN，必需** |

社区列表只有"拦"这一种动作。要保住 `r.stripe.com`，唯一的办法是**整域放行 `@@||stripe.com^`** ——而那会连带放过 `stats.stripe.com` 等追踪端点。这就是社区列表无法解决的取舍。

### 2. 规则形式单一：99.6% 是树形拦截

实测社区 10 个列表共 215 万条规则的形式分布：

| 形式 | 条数 | 占比 | 语义 |
|---|---|---|---|
| `\|\|domain^` | 2,156,349 | **99.6%** | 拦整棵子树 |
| `0.0.0.0 domain` | 76,104 | 0.4% | 只拦该主机名 |
| `@@` 放行 | 216 | — | 会压过拦截 |
| 正则 | 32 | — | — |

`||domain^` 表达不了"精确放行这一个主机名、但仍拦它的其他子域"。

### 3. 放行规则会压过拦截，且无法反制

`AdGuard DNS filter` 自带 **216 条 `@@` 放行**（如 `@@||aax-fe.amazon.co.jp^`、`@@||app.adjust.com^`）。这些放行会**压制普通拦截规则**——这正是 `app.adjust.com` 必须加 `$important` 才能拦住的原因。

社区列表对此**无能为力**：它只能"别把这个域名列进黑名单"，属于被动规避。

---

## 二、我们的做法

### 1. 意图分层

规则集显式分为两层，**分层即文档**：

```
第一层 FORCE-ALLOW  @@||x^$important   业务必需放行（精确到主机名）
第二层 FORCE-BLOCK  ||x^$important      纯追踪 / 垃圾广告拦截
```

### 2. 强制语义（核心）与 AGH 的实现限制

`$important` 是 AdGuard 规则的**最高优先级**修饰符，但**它在哪里生效有限制**。这是本项目在旁路由上做的对照实验结论：

| 规则位置 | `@@\|\|x^$important` 放行 | `\|\|x^$important` 拦截 |
|---|---|---|
| **user_rules**（自定义规则） | ✅ **生效** | ✅ 生效 |
| **外部列表文件** | ❌ **无效** | ✅ **生效** |

实测证据：

```
同一条 @@||an.facebook.com^$important
  放 user_rules  →  57.144.96.141   (放行成功)
  放列表文件      →  0.0.0.0         (仍被社区列表拦截)

同一条 ||api.taboola.com^$important
  放列表文件      →  0.0.0.0         (成功压过 AdGuard DNS filter 的 @@||api.taboola.com^ 放行)
```

因此本项目产出**四个文件**（两侧规则集共用同一真源）：

| 文件 | 内容 | 用途 |
|---|---|---|
| `rules.txt` | 113 条拦截规则 `||x^$important` | AGH 外部列表订阅 |
| `user_rules.yaml` | 13 条**当前真正需要**的放行规则 `@@||x^$important` | 注入 AGH 的 `user_rules` 段 |
| `watchlist.txt` | 142 条观察名单 | 上游列表更新导致误伤时，把域名加入生成器 `ACTIVE_DOMAINS` 再启用 |
| `business_allow.yaml` | 3 条 Clash 侧同源放行（域名→策略组） | `oc-adapt.py` 读取，插在 `RULE-SET,reject,REJECT` 前 |

社区列表做不到前者——它们只能靠"不列入黑名单"被动规避，且无法压过其他列表的放行。

### 3. 精确粒度

- **放行**：精确到主机名（`@@||r.stripe.com^`），不做整域放行 → 不连带放过追踪端点
- **拦截**：用 `||` 覆盖子域树 → 新出现的追踪端点自动覆盖，无需人工维护

### 4. 可审计

- 每条规则带分类注释
- `gen-own-ruleset.py` 是唯一真源，四个产物都由它生成，可复现
- 2026-11-24 源头审计：155 条放行中只有 13 条被当前 27 个启用列表或 Clash reject 真正需要，其余进观察名单，不再无差别覆盖
- 分类结构对应到具体业务场景，不是按域名来源分类

---

## 三、覆盖范围

### 业务必需放行（13 条，`user_rules.yaml`）

| 分类 | 条数 | 典型内容 |
|---|---|---|
| 投放 / 广告后台 | 10 | `adservice.google.com`、`googleadservices.com`、`googlesyndication.com`、`googleads.g.doubleclick.net`、`googletagmanager.com`、`ads-twitter.com`、`amazon-adsystem.com`、`gdt.qq.com`、`e.qq.com`、`ads.tiktok.com` |
| TikTok / 抖音主站 | 1 | `analytics.tiktok.com` |
| 支付 / 风控 | 1 | `sc-static.net` |
| 社媒登录回跳 | 1 | `an.facebook.com` |

> 完整业务域名定义仍保留在生成器的 `FORCE_ALLOW`（155 条），未删除；只是不再全部注入 AGH。

### 纯追踪 / 广告拦截（113 条，`rules.txt`）

| 分类 | 条数 | 典型内容 |
|---|---|---|
| Meta 追踪端点 | 14 | `pixel.facebook.com`、`star.c10r.facebook.com`、`tr.facebook.com` |
| 字节系日志上报 | 22 | `log*.amemv.com`、`rtlog3-applog-*.amemv.com`、`mcs-tiktok.byteoversea.net` |
| 字节系广告归因 | 28 | `ads.us.tiktok.com`、`analytics*.tiktok.com`、`pangle.io` |
| 分析归因 SDK | 15 | `appsflyer.com`、`adjust.com`、`amplitude`、`mixpanel`、`segment.io` |
| 谷歌系分析广告 | 7 | `analytics.google.com`、`ssl.google-analytics.com`、`ad.doubleclick.cn` |
| 微软系遥测 | 13 | `activity.windows.com`、`applicationinsights.io`、`events.data.microsoft.com` |
| 设备遥测补位 | 2 | `cl2.apple.com`、`smoot.apple.com` |
| 其他广告 / 错误上报 | 2 | `bat.bing.com`、`sentry.io` |

---

## 四、使用方法

### AdGuard Home

**第一步**：在 **Filters → Add blocklist** 添加拦截层：

```
https://cdn.jsdelivr.net/gh/DMaiGit/agh-rules-cn@main/rules.txt
```

> 用 jsDelivr 而非 raw.githubusercontent.com —— 后者有 CDN 缓存延迟，实测会拿到旧版本。

**第二步**：把 `user_rules.yaml` 的内容注入 **AdGuard Home → 设置 → 过滤器设置 → 自定义过滤规则**，覆盖原有内容。

> 这一步不可省略：业务放行规则依赖 `$important`，而 `$important` 放行只在 `user_rules` 中生效。

**一键脚本**（在 OpenClash 路由器上执行）：

```bash
# 下载放行层并替换 user_rules 段
curl -s https://cdn.jsdelivr.net/gh/DMaiGit/agh-rules-cn@main/user_rules.yaml \
  | grep -v '^#' | grep -v '^$' > /tmp/ur.txt
```

### 与社区列表配合使用

推荐组合（自测 23/23 全通过）：

| 层级 | 列表 | 作用 |
|---|---|---|
| 底座 | HaGeZi Multi Normal | 通用广告与追踪 |
| 底座 | AdGuard DNS filter | 通用域名规则 |
| 底座 | HaGeZi Threat Intelligence (Medium) | 威胁情报 |
| ~~专项~~ | ~~ShadowWhisperer Tracking~~ | **已于 2026-11-24 停用**：对 `googletagmanager.com`、`safebrowsing.googleapis.com`、`cdn-go.cn`、`autonavi.com`、`ip.cn`、`ip138.com`、`ifconfig.me`、`gateway.instagram.com` 做**整域拦截**，实测造成腾讯文档 CDN、高德、IP 查询、Chrome 安全浏览、Instagram 不可用 || 专项 | Steven Black List | 追踪 + 恶意域名 |
| 中文广告 | CHN: anti-AD | 中文站点广告专项 |
| 弹窗广告 | AdGuard DNS Popup Hosts | 弹窗站点（$dnsrewrite） |
| 短链追踪 | HaGeZi URL Shortener | 国内短链服务 |
| 设备遥测 | Apple/Vivo/LG/Huawei/OPPO Tracker | 各品牌设备遥测 |
| 安全 | Anti-Malware / URLHaus / ShadowWhisperer Malware | 恶意软件 |
| **本项目** | **agh-rules-cn** | **业务感知分层，强制语义** |

社区列表负责**广度**，本列表负责**语义与精度**。由于本列表的规则都带 `$important`，无论社区列表如何更新，本列表的业务放行与追踪拦截**始终生效**。

---

## 五、生成与维护

```bash
python3 gen-own-ruleset.py
```

`rules.txt` 由脚本生成，**请勿直接手改**。要增删规则，改脚本里的 `FORCE_ALLOW` / `FORCE_BLOCK` 字典后重新生成。

目录结构：

```
agh-rules-cn/
├── README.md              本文件
├── rules.txt              生成产物: 拦截层 (AGH 外部列表订阅)
├── user_rules.yaml        生成产物: 放行层 (13 条, 注入 AGH user_rules 段)
├── watchlist.txt          生成产物: 观察名单 (142 条, 不注入)
├── business_allow.yaml    生成产物: OpenClash 侧同源放行 (oc-adapt.py 读取)
├── gen-own-ruleset.py     规则真源 + 生成器
└── .github/workflows/     CI: 一致性校验 + 分层校验 + 业务零误伤校验
```

---

## 六、免责声明

本规则集基于公开可观测的域名行为整理，仅拦截**明确的**追踪与广告端点，不做泛化拦截。使用前请根据自己的业务场景验证。规则中涉及的商标与服务归各自权利人所有。
