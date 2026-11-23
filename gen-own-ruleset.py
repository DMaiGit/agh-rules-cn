#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成自有 AGH 规则集 —— v2 双产物架构 (2026-11-22 实测校正)。

【实测发现的 AGH 实现限制】(在旁路由上做的对照实验):
  | 规则位置            | @@||x^$important 放行 | ||x^$important 拦截 |
  |---------------------|-----------------------|---------------------|
  | user_rules (自定义) | ✅ 生效              | ✅ 生效             |
  | 外部列表文件        | ❌ 无效              | ✅ 生效             |

  证据: 同一条 @@||an.facebook.com^$important
        放 user_rules  → 57.144.96.141 (放行成功)
        放列表文件      → 0.0.0.0        (仍被社区列表拦截)
  同一条 ||api.taboola.com^$important
        放列表文件      → 0.0.0.0 (成功压过 AdGuard DNS filter 的 @@||api.taboola.com^ 放行)

因此产出两个文件:
  rules.txt       —— 订阅用外部列表。只含拦截规则 (||x^$important)。
                     这类规则在列表文件里依然生效, 且能压过社区列表的 @@ 放行。
  user_rules.yaml —— 业务必需放行规则 (@@||x^$important), 需注入 AGH 的
                     user_rules 段才能生效。

与社区列表的根本差异:
  1) 意图分层 —— 社区是扁平"拉黑集合", 无法表达"同主域下广告子域要拦、
     功能子域要放行"; 本列表显式分为业务放行层与追踪拦截层。
  2) 强制语义 —— 拦截层用 ||x^$important, 压过社区列表里的 @@ 放行。
  3) 精确粒度 —— 放行精确到主机名, 不做整域放行; 拦截用 || 覆盖子域树。
  4) 可审计   —— 每条规则带分类注释, 生成脚本即真源, 可复现。
"""
import os, re, sys, datetime

# 产物目录：默认脚本所在目录（仓库根 / CI 环境）；本机若存在 own-ruleset 子目录则用它。
# 也可用环境变量 AGH_RULES_OUT 显式指定。
_HERE = os.path.dirname(os.path.abspath(__file__))
_SUB = os.path.join(_HERE, 'own-ruleset')
OUT_DIR = os.environ.get('AGH_RULES_OUT') or (_SUB if os.path.isdir(_SUB) else _HERE)
os.makedirs(OUT_DIR, exist_ok=True)

GENERATED = datetime.date.today().isoformat()

# ------------------------------------------------------------------
# 单一真源：两侧规则集共用同一份「业务必需域名」定义
# ------------------------------------------------------------------
# ACTIVE_DOMAINS：在当前 27 个启用 AGH 列表 + Clash reject 规则集下，
#                 实测确实被拦截、必须放行的域名（2026-11-24 源头审计）。
# 其余 FORCE_ALLOW 条目不注入 AGH，只写入 watchlist.txt 作为观察名单：
# 上游列表更新导致误伤时，把域名加进 ACTIVE_DOMAINS 并重新生成即可。
ACTIVE_DOMAINS = {
    'adservice.google.com', 'googleadservices.com', 'googlesyndication.com',
    'googleads.g.doubleclick.net', 'googletagmanager.com', 'ads-twitter.com',
    'amazon-adsystem.com', 'gdt.qq.com', 'e.qq.com', 'ads.tiktok.com',
    'analytics.tiktok.com', 'sc-static.net', 'an.facebook.com',
}

# Clash 侧同源放行：域名 -> 目标策略组。由 oc-adapt.py 读取并生成
# DOMAIN-SUFFIX 规则（插在 RULE-SET,reject,REJECT 之前）。
# ttwstatic.com 是路由归属修正（TikTok 静态资源原落 proxy_ls → 通用代理），
# 另外两条是抵消 Loyalsoldier reject 的过宽拦截。
CLASH_ALLOW = {
    'sc-static.net': '💳 Stripe',
    'googletagmanager.com': '🚀 PROXY',
    'ttwstatic.com': '📱 TikTok',
}

# ==================================================================
# 一、业务必需放行层 (FORCE-ALLOW)
# ==================================================================
FORCE_ALLOW = {
'投放 / 广告后台（业务必需，广告主无法登录投放平台等于无法投放）': [
    '@@||ads.google.com^',
    '@@||adservice.google.com^',
    '@@||googleadservices.com^',
    '@@||googlesyndication.com^',
    '@@||googleads.g.doubleclick.net^',
    '@@||googletagmanager.com^',
    '@@||ads-twitter.com^',
    '@@||amazon-adsystem.com^',
    '@@||shie.com.cn^',
    '@@||gdt.qq.com^',
    '@@||e.qq.com^',
    '@@||ads.tiktok.com^',
    '@@||ads-sg.business-tiktok.com^',
    '@@||ads-va.business-tiktok.com^',
    '@@||ads-api.tiktok.com^',
    '@@||ads-tiktok.com^',
    '@@||ads.union.tiktokv.com^',
    '@@||business.tiktok.com^',
    '@@||business-api.tiktok.com^',
    '@@||ad.toutiao.com^',
    '@@||ads.toutiao.com^',
    '@@||open.douyin.com^',
    '@@||qianchuan.jinritemai.com^',
    '@@||business.oceanengine.com^',
    '@@||ad.xiaohongshu.com^',
    '@@||ad.weixin.qq.com^',
    '@@||e.weibo.com^',
    '@@||ads.kuaishou.com^',
    '@@||e.kuaishou.com^',
    '@@||cm.bilibili.com^',
],
'TikTok / 抖音 主站 API 与内容分发（精确放行，不用整域，避免连带放过 ads 子域）': [
    '@@||analytics.tiktok.com^',
    '@@||api.tiktokv.com^',
    '@@||api16-normal-useast5.us.tiktokv.com^',
    '@@||api22-normal-useast2.us.tiktokv.com^',
    '@@||api16-normal-useast1.us.tiktokv.com^',
    '@@||api19-normal-useast5.us.tiktokv.com^',
    '@@||api21-normal-useast5.us.tiktokv.com^',
    '@@||api16-normal-alisg1.tiktokv.com^',
    '@@||api16-normal-useast5.tiktokv.com^',
    '@@||api16-normal-c-useast1a.tiktokv.com^',
    '@@||v16-webapp.tiktokv.com^',
    '@@||v19-webapp.tiktokv.com^',
    '@@||v16-webapp-prime.tiktokv.com^',
    '@@||v19-webapp-prime.tiktokv.com^',
    '@@||tiktokcdn-us.com^',
    '@@||tiktokcdn.com^',
    '@@||tiktokv-us.com^',
    '@@||mcs.tiktokv.com^',
    '@@||mcs-us.tiktokv.com^',
    '@@||mcs-ttp2.tiktokv.com^',
],
'支付链路（Stripe / PayPal / Wise / Payoneer 的回调与 API）': [
    '@@||js.stripe.com^',
    '@@||r.stripe.com^',
    '@@||m.stripe.com^',
    '@@||q.stripe.com^',
    '@@||t.stripe.com^',
    '@@||api.stripe.com^',
    '@@||js.stripe.network^',
    '@@||m.stripe.network^',
    '@@||checkout.stripe.com^',
    '@@||paypal.com^',
    '@@||www.paypal.com^',
    '@@||api.paypal.com^',
    '@@||api-m.paypal.com^',
    '@@||www.sandbox.paypal.com^',
    '@@||wise.com^',
    '@@||www.wise.com^',
    '@@||transferwise.com^',
    '@@||api.wise.com^',
    '@@||payoneer.com^',
    '@@||www.payoneer.com^',
    '@@||api.payoneer.com^',
],
'电商后台与卖家工具（登录态、商品同步、订单查询）': [
    '@@||sellercentral.amazon.com^',
    '@@||sellercentral.amazon.co.jp^',
    '@@||sellercentral.amazon.co.uk^',
    '@@||sellercentral-europe.amazon.com^',
    '@@||s3.amazonaws.com^',
    '@@||api.etsy.com^',
    '@@||openapi.etsy.com^',
    '@@||www.etsy.com^',
    '@@||api.shopify.com^',
    '@@||shopify.com^',
    '@@||www.shopify.com^',
    '@@||admin.shopify.com^',
    '@@||api.ebay.com^',
    '@@||api.walmart.com^',
    '@@||developer.api.ebay.com^',
],
'企业协作与开发工具（登录、CI、CDN、包管理）': [
    '@@||github.com^',
    '@@||api.github.com^',
    '@@||objects.githubusercontent.com^',
    '@@||raw.githubusercontent.com^',
    '@@||codeload.github.com^',
    '@@||gitlab.com^',
    '@@||api.slack.com^',
    '@@||slack.com^',
    '@@||discord.com^',
    '@@||discordapp.com^',
    '@@||atlassian.net^',
    '@@||registry.npmjs.org^',
    '@@||npmjs.com^',
    '@@||pypi.org^',
    '@@||files.pythonhosted.org^',
    '@@||repo.anaconda.com^',
    '@@||conda.anaconda.org^',
],
'IP 查询与网络诊断工具（面板定位/延迟测速要用；ShadowWhisperer 把公共 IP API 全按指纹追踪拦了）': [
    '@@||ip.sb^',
    '@@||ipify.org^',
    '@@||ipinfo.io^',
    '@@||ipapi.is^',
    '@@||ipwho.is^',
    '@@||ipip.net^',
    '@@||ip.cn^',
    '@@||ip138.com^',
    '@@||ifconfig.me^',
    '@@||whois.pconline.com.cn^',
    '@@||cloudflareperf.com^',
],
'社区列表整域误伤修正（基础设施 / 鉴权 / 支付风控域名，并非追踪；2026-11-24 查询日志实证）': [
    '@@||dns.iqiyi.com^',
    '@@||dns.weixin.qq.com.cn^',
    '@@||aedns.weixin.qq.com^',
    '@@||cdn-go.cn^',
    '@@||cdn.staticfile.org^',
    '@@||tliveapp.com^',
    '@@||metacubex.one^',
    '@@||graph.instagram.com^',
    '@@||gateway.instagram.com^',
    '@@||sc-static.net^',
],
'社媒登录回跳端点（社区列表会拦掉，导致无法登录）': [
    '@@||an.facebook.com^',
    '@@||tr.facebook.com^',
    '@@||m.facebook.com^',
    '@@||touch.facebook.com^',
    '@@||b-api.facebook.com^',
    '@@||edge-m.facebook.com^',
    '@@||graph.facebook.com^',
    '@@||graph-video.facebook.com^',
    '@@||graph.facebook.net^',
    '@@||connect.facebook.net^',
],
'AI 服务（Claude / ChatGPT / Gemini 及其 API）': [
    '@@||anthropic.com^',
    '@@||api.anthropic.com^',
    '@@||claude.ai^',
    '@@||openai.com^',
    '@@||api.openai.com^',
    '@@||chatgpt.com^',
    '@@||chat.openai.com^',
    '@@||gemini.google.com^',
    '@@||generativelanguage.googleapis.com^',
    '@@||perplexity.ai^',
],
'流媒体播放与鉴权（部分平台把 CDN / 鉴权域名与广告域名混在同一主域下）': [
    '@@||netflix.com^',
    '@@||www.netflix.com^',
    '@@||api.netflix.com^',
    '@@||disneyplus.com^',
    '@@||www.disneyplus.com^',
    '@@||spotify.com^',
    '@@||api.spotify.com^',
    '@@||youtube.com^',
    '@@||www.youtube.com^',
    '@@||googlevideo.com^',
    '@@||twitch.tv^',
],
}

# ==================================================================
# 二、纯追踪 / 垃圾广告拦截层 (FORCE-BLOCK)
# ==================================================================
FORCE_BLOCK = {
'Meta 追踪端点（pixel / star / edge 家族，广告与登录追踪）': [
    '||pixel.facebook.com^',
    '||pixel.facebook.net^',
    '||edge-f.facebook.com^',
    '||star.c10r.facebook.com^',
    '||star-mini.c10r.facebook.com^',
    '||star.fallback.c10r.facebook.com^',
    '||star-mini.fallback.c10r.facebook.com^',
    '||star.fallback.c10r.instagram.com^',
    '||star-mini-nohsts.c10r.facebook.com^',
    '||star-nohsts.c10r.facebook.com^',
    '||analytics.facebook.com^',
    '||ads.facebook.com^',
],
'字节系日志上报 / 归因（log / rtlog / mon 全系列）': [
    '||log.amemv.com^',
    '||log0-misc-hl.amemv.com^',
    '||log0-misc-lf.amemv.com^',
    '||log0-misc-lq.amemv.com^',
    '||log3-misc-hl.amemv.com^',
    '||log3-misc-lf.amemv.com^',
    '||log3-misc-lq.amemv.com^',
    '||log5-misc-hl.amemv.com^',
    '||log5-misc-lf.amemv.com^',
    '||log5-misc-lq.amemv.com^',
    '||logbk.amemv.com^',
    '||rtlog3-applog-hl.amemv.com^',
    '||rtlog3-applog-lf.amemv.com^',
    '||rtlog3-applog-lq.amemv.com^',
    '||log-tiktok.byteoversea.net^',
    '||log-tiktok.byteoversea.net.bpgslb.com^',
    '||mcs-tiktok.byteoversea.net^',
    '||log9-normal-c-useast1a.tiktokv.com.ecdnx.com^',
    '||tiktok.tray.com.br^',
    '||tnc3-aliec2.bytedance.com^',
    '||tnc3-alisc1.bytedance.com^',
    '||tnc3-bjlgy.bytedance.com^',
],
'字节系广告与归因（ads / analytics / pangle）': [
    '||ads.us.tiktok.com^',
    '||ads.in.tiktok.com^',
    '||ads.ttp2.us.tiktok.com^',
    '||ads-ttp2.us.tiktok.com^',
    '||ads-ttp2.tiktokw.eu.edgesuite.net^',
    '||ads-sg.business-tiktok.com.edgesuite.net^',
    '||analytics-ipv6.tiktokw.us^',
    '||analytics-sg.tiktok.com^',
    '||analytics.us.tiktok.com^',
    '||ad-instantpage-sg.tiktokv.com.edgekey.net^',
    '||mon-boot.tiktokv.com.edgekey.net^',
    '||analytics.tiktok.com.edgekey.net^',
    '||analytics-attribution-va.tiktok.com.edgekey.net^',
    '||analytics-exp-i18n.tiktok.com.edgekey.net^',
    '||analytics-exp-sg.tiktok.com.edgekey.net^',
    '||analytics-i18n.tiktok.com.edgekey.net^',
    '||analytics-sg.tiktok.com.edgekey.net^',
    '||analytics.us.tiktok.com.bytedance.akadns.net^',
    '||analytics.us.tiktok.com.bytewlb.akadns.net^',
    '||analytics.tiktok.com.bytewlb.akadns.net^',
    '||analytics.us.tiktok.com-row.bytewlb.akadns.net^',
    '||analytics.us.tiktok.com.edgesuite.net^',
    '||load.api.viradatiktokshop.com^',
    '||ad.tiktokv.us^',
    '||pangle.io^',
    '||pangle-b.io^',
    '||pangle.io.edgekey.net^',
    '||analytics.pangle-ads.com^',
    '||tiktokpangle.us^',
],
'分析归因 SDK（第三方埋点，全量拦截）': [
    '||appsflyer.com^',
    '||app.adjust.com^',
    '||adjust.com^',
    '||api.amplitude.com^',
    '||api2.amplitude.com^',
    '||api.mixpanel.com^',
    '||api.segment.io^',
    '||cdn.segment.com^',
    '||api.heap.io^',
    '||heapanalytics.com^',
    '||matomo.cloud^',
    '||api.branch.io^',
    '||static.cognitivetracking.com^',
    '||cdn.cognitivetracking.com^',
    '||sb.scorecardresearch.com^',
],
'谷歌系分析与广告（Google Analytics / Firebase / DoubleClick）': [
    '||analytics.google.com^',
    '||ssl.google-analytics.com^',
    '||www.google-analytics.com^',
    '||app-measurement.com^',
    '||firebase-settings.crashlytics.com^',
    '||stats.g.doubleclick.net^',
    '||ad.doubleclick.cn^',
],
'微软系遥测（Windows 活动 / Application Insights）': [
    '||mobile.events.data.microsoft.com^',
    '||self.events.data.microsoft.com^',
    '||v10.events.data.microsoft.com^',
    '||v20.events.data.microsoft.com^',
    '||events.data.microsoft.com^',
    '||activity.windows.com^',
    '||assets.activity.windows.com^',
    '||edge.activity.windows.com^',
    '||settings.data.microsoft.com^',
    '||ppe.activity.windows.com^',
    '||applicationinsights.io^',
    '||loganalytics.io^',
    '||js.monitor.azure.com^',
],
'设备遥测补位（原由 ShadowWhisperer Tracking 覆盖，该列表 2026-11-24 因整域误伤停用）': [
    '||cl2.apple.com^',
    '||smoot.apple.com^',
],
'其他广告与错误上报': [
    '||bat.bing.com^',
    '||sentry.io^',
],
'CRM / 营销自动化 / 邮件追踪': [
    '||hubspot.com^',
    '||klaviyo.com^',
    '||marketo.com^',
    '||pardot.com^',
    '||customer.io^',
    '||mailchimp.com^',
    '||sendgrid.net^',
],
'被社区列表 @@ 放行的广告平台（用 $important 反制）': [
    '||api.taboola.com^',
    '||trc.taboola.com^',
    '||cdn.taboola.com^',
    '||ads.taboola.com^',
],
}

# ==================================================================
# 三、生成
# ==================================================================
import argparse

def add_imp(rule):
    if rule.startswith('@@'):
        return rule
    if '$' in rule:
        return rule
    return rule + '$important'

def add_imp_allow(rule):
    if rule.startswith('@@'):
        if '$' in rule:
            return rule
        return rule + '$important'
    return rule

lines = []
lines.append('! ============================================================')
lines.append('! 自有 AGH 规则集 — 面向中文网络环境的业务感知过滤')
lines.append('! 生成日期: ' + GENERATED)
lines.append('! 生成器: gen-own-ruleset.py (规则真源, 请勿直接手改本文件)')
lines.append('! 语法: AdGuard Home Adblock 语法 (与浏览器扩展兼容)')
lines.append('!')
lines.append('! 与社区列表的根本差异:')
lines.append('!   1) 意图分层 —— 社区是扁平"拉黑集合", 无法表达"同主域下广告子域要拦、')
lines.append('!      功能子域要放行"; 本列表显式分为业务放行层与追踪拦截层。')
lines.append('!   2) 强制语义 —— 拦截层用 ||x^$important, 压过社区列表里的 @@ 放行。')
lines.append('!      实测: api.taboola.com 从 151.101.65.44 → 0.0.0.0。')
lines.append('!   3) 精确粒度 —— 放行精确到主机名, 不做整域放行; 拦截用 || 覆盖子域树。')
lines.append('!   4) 可审计   —— 每条规则带分类注释, 生成脚本即真源。')
lines.append('! ============================================================')
lines.append('')
lines.append('! NOTE: 业务必需放行规则在 user_rules.yaml。')
lines.append('!       实测确认 $important 放行在外部列表文件中不生效, 仅 user_rules 有效。')
lines.append('')

lines.append('! ###########################################################')
lines.append('! ## 纯追踪 / 垃圾广告拦截 (FORCE-BLOCK)')
lines.append('! ## ||x^$important —— 强制拦截, 可压过社区列表的 @@ 放行')
lines.append('! ###########################################################')
lines.append('')
n_block = 0
for cat, rules in FORCE_BLOCK.items():
    lines.append('! --- ' + cat + ' ---')
    for r in rules:
        lines.append(add_imp(r))
        n_block += 1
    lines.append('')

text = '\n'.join(lines).rstrip() + '\n'
rules_path = os.path.join(OUT_DIR, 'rules.txt')

# ---------- user_rules.yaml: 业务放行规则 (需注入 AGH 的 user_rules 段) ----------
ur_lines = ['# 自有 AGH 规则集 — 业务必需放行层',
            '# 注入方式: 替换 AGH 配置 user_rules: 段的全部内容',
            '# 原因: 实测确认 $important 放行仅在 user_rules 中生效',
            '# 生成器: gen-own-ruleset.py (请勿手改)',
            '']
def _allowed_domain(rule):
    m = re.match(r'^@@\|\|(.*?)\^', rule)
    return m.group(1).lower() if m else ''

n_allow = n_watch = 0
watch_lines = ['# 观察名单：当前上游列表组合下无需注入 AGH 的业务域名',
               '# 上游列表更新导致误伤时，把域名加入生成器 ACTIVE_DOMAINS 即可',
               '# 生成器: gen-own-ruleset.py (请勿手改)', '']
for cat, rules in FORCE_ALLOW.items():
    active = [r for r in rules if _allowed_domain(r) in ACTIVE_DOMAINS]
    watch = [r for r in rules if _allowed_domain(r) not in ACTIVE_DOMAINS]
    n_allow += len(active); n_watch += len(watch)
    if active:
        ur_lines.append("  - '! --- " + cat + " ---'")
        for r in active:
            ur_lines.append("  - '" + add_imp_allow(r).replace("'", "''") + "'")
    if watch:
        watch_lines.append('! --- ' + cat + ' ---')
        watch_lines.extend(watch)
        watch_lines.append('')
ur_text = '\n'.join(ur_lines) + '\n'
ur_path = os.path.join(OUT_DIR, 'user_rules.yaml')
watch_path = os.path.join(OUT_DIR, 'watchlist.txt')
open(watch_path, 'w', encoding='utf-8').write('\n'.join(watch_lines).rstrip() + '\n')

# ---- business_allow.yaml：OpenClash 侧同源放行（oc-adapt.py 读取）----
ca_lines = ['# 由 gen-own-ruleset.py 生成，请勿手改',
            '# oc-adapt.py 读取本文件，在 RULE-SET,reject,REJECT 之前插入 DOMAIN-SUFFIX 规则',
            'version: 1', 'rules:']
for dom, policy in CLASH_ALLOW.items():
    ca_lines.append("  - 'DOMAIN-SUFFIX,%s,%s'" % (dom, policy))
ca_text = '\n'.join(ca_lines) + '\n'
ca_path = os.path.join(OUT_DIR, 'business_allow.yaml')
open(ca_path, 'w', encoding='utf-8').write(ca_text)

ap = argparse.ArgumentParser()
ap.add_argument('--check', action='store_true',
                help='只校验 rules.txt 是否与生成器一致, 不写入')
ap.add_argument('--out-dir', default=OUT_DIR, help='输出目录')
args = ap.parse_args()

if args.check:
    # CI 模式: 与仓库中的产物比对
    def _norm(s):
        # 忽略「生成日期」行：否则跨天后校验必然失败（内容相同、日期不同）
        return '\n'.join(l for l in s.splitlines() if not l.startswith('! 生成日期:'))

    ok = True
    for fn, content in [(os.path.basename(rules_path), text),
                        (os.path.basename(ur_path), ur_text),
                        (os.path.basename(watch_path), open(watch_path, encoding='utf-8').read()),
                        (os.path.basename(ca_path), ca_text)]:
        repo = os.path.join(OUT_DIR, fn)
        if not os.path.exists(repo):
            print(f'✗ 未找到 {fn}'); ok = False; continue
        if _norm(open(repo, encoding='utf-8').read()) != _norm(content):
            print(f'✗ {fn} 与生成器输出不一致, 请运行 python3 gen-own-ruleset.py 后提交')
            ok = False
    if ok:
        print('✓ 产物与生成器一致')
    sys.exit(0 if ok else 1)

open(rules_path, 'w', encoding='utf-8').write(text)
open(ur_path, 'w', encoding='utf-8').write(ur_text)

print('=== 生成完成 ===')
print(f'  rules.txt        拦截 {n_block} 条 ({os.path.getsize(rules_path)} 字节) — 订阅用')
print(f'  user_rules.yaml  放行 {n_allow} 条 ({os.path.getsize(ur_path)} 字节) — 注入 user_rules')
print(f'  watchlist.txt    观察 {n_watch} 条 — 不注入, 上游误伤时启用')
print(f'  business_allow.yaml Clash 放行 {len(CLASH_ALLOW)} 条 — oc-adapt.py 读取')

allr = [l for l in lines if l and not l.startswith('!')]
all_allow = [r for rs in FORCE_ALLOW.values() for r in rs]
dup = sorted({r for r in allr + all_allow if (allr + all_allow).count(r) > 1})
print(f'  重复规则: {dup if dup else "无"}')
bad = [r for r in allr + all_allow if not re.match(r'^(@@)?\|\|[^*]+\^(\$[a-z,]+)?$', r)]
print(f'  语法异常: {bad if bad else "无"}')

# 冲突检查: 同一域名不能同时出现在放行层与拦截层
def dom_of(r):
    m = re.match(r'^(@@)?\|\|([^*]+)\^', r)
    return m.group(2).lower() if m else None

allow_d = {dom_of(r) for r in all_allow if dom_of(r)}
block_r = [r for r in allr if not r.startswith('@@')]
conflict = [r for r in block_r if dom_of(r) in allow_d]
if conflict:
    print(f'  !! 放行/拦截冲突 ({len(conflict)} 条), 必须人工裁决:')
    for c in conflict: print('     ', c)
    sys.exit(1)
print('  放行/拦截冲突: 无')

print()
print('  业务覆盖统计:')
for d in ['tiktok','stripe','paypal','amazon','etsy','shopify','github','anthropic','netflix','douyin','facebook']:
    c = sum(1 for r in all_allow if d in r.lower())
    if c: print(f'    {d:<12} 放行 {c} 条')
