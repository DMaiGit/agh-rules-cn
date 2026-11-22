# agh-rules-cn — 面向中文网络环境的业务感知 AdGuard Home 规则集

> 电商、支付、流媒体、AI 的业务链路**零误伤**；纯追踪与垃圾广告**强制拦截**。
> 与社区列表的根本差异不在"拦得多"，而在**能表达意图**。

[![规则数](https://img.shields.io/badge/rules-213-blue)](rules.txt)
[![语法](https://img.shields.io/badge/syntax-AdGuard%20Adblock-green)](rules.txt)
[![生成](https://img.shields.io/badge/generated-auto--update-blue)](gen-own-ruleset.py)

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

### 2. 强制语义（核心）

`$important` 是 AdGuard 规则的**最高优先级**修饰符：

- `@@||x^$important` → **强制放行**，压过任何列表的 `||` 拦截
- `||x^$important` → **强制拦截**，压过任何列表的 `@@` 放行

**这已在本机实测验证**：

```
实验前:  r.stripe.com  →  0.0.0.0        (被社区列表拦截)
实验后:  r.stripe.com  →  54.187.159.182 (强制放行成功)
```

社区列表做不到这件事——它们只能靠"不列入黑名单"被动规避，且无法压过其他列表的放行。

### 3. 精确粒度

- **放行**：精确到主机名（`@@||r.stripe.com^`），不做整域放行 → 不连带放过追踪端点
- **拦截**：用 `||` 覆盖子域树 → 新出现的追踪端点自动覆盖，无需人工维护

### 4. 可审计

- 每条规则带分类注释
- `gen-own-ruleset.py` 是唯一真源，`rules.txt` 由它生成，可复现
- 分类结构对应到具体业务场景，不是按域名来源分类

---

## 三、覆盖范围

### 业务必需放行（110 条）

| 分类 | 条数 | 典型内容 |
|---|---|---|
| 投放 / 广告后台 | 16 | `ads.google.com`、`ads.tiktok.com`、`business.tiktok.com`、`amazon-adsystem.com` |
| TikTok / 抖音主站 API | 21 | `api.tiktokv.com`、`api16-normal-*.tiktokv.com`、`mcs.tiktokv.com` |
| 支付链路 | 21 | `r.stripe.com`、`js.stripe.com`、`api.paypal.com`、`api.wise.com` |
| 电商后台 / 卖家工具 | 14 | `sellercentral.amazon.com`、`api.etsy.com`、`api.shopify.com` |
| 企业协作 / 开发工具 | 14 | `github.com`、`registry.npmjs.org`、`files.pythonhosted.org` |
| AI 服务 | 10 | `anthropic.com`、`api.openai.com`、`generativelanguage.googleapis.com` |
| 流媒体鉴权 | 11 | `netflix.com`、`api.spotify.com`、`googlevideo.com` |

### 纯追踪 / 广告拦截（103 条）

| 分类 | 条数 | 典型内容 |
|---|---|---|
| Meta 追踪端点 | 14 | `pixel.facebook.com`、`star.c10r.facebook.com`、`tr.facebook.com` |
| 字节系日志上报 | 22 | `log*.amemv.com`、`rtlog3-applog-*.amemv.com`、`mcs-tiktok.byteoversea.net` |
| 字节系广告归因 | 28 | `ads.us.tiktok.com`、`analytics*.tiktok.com`、`pangle.io` |
| 分析归因 SDK | 15 | `appsflyer.com`、`adjust.com`、`amplitude`、`mixpanel`、`segment.io` |
| 谷歌系分析广告 | 7 | `analytics.google.com`、`ssl.google-analytics.com`、`ad.doubleclick.cn` |
| 微软系遥测 | 13 | `activity.windows.com`、`applicationinsights.io`、`events.data.microsoft.com` |
| 其他广告 / 错误上报 | 3 | `bat.bing.com`、`sc-static.net`、`sentry.io` |

---

## 四、使用方法

### AdGuard Home

在 **Filters → Add blocklist** 添加：

```
https://raw.githubusercontent.com/DMaiGit/agh-rules-cn/main/rules.txt
```

### 与社区列表配合使用

推荐组合（自测 23/23 全通过）：

| 层级 | 列表 | 作用 |
|---|---|---|
| 底座 | HaGeZi Multi Normal | 通用广告与追踪 |
| 底座 | AdGuard DNS filter | 通用域名规则 |
| 底座 | HaGeZi Threat Intelligence (Medium) | 威胁情报 |
| 专项 | ShadowWhisperer Tracking | 追踪器专项 |
| 专项 | Steven Black List | 追踪 + 恶意域名 |
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
├── rules.txt              生成产物 (AGH 可直接订阅)
├── gen-own-ruleset.py     规则真源 + 生成器
└── .github/workflows/     自动校验
```

---

## 六、免责声明

本规则集基于公开可观测的域名行为整理，仅拦截**明确的**追踪与广告端点，不做泛化拦截。使用前请根据自己的业务场景验证。规则中涉及的商标与服务归各自权利人所有。
