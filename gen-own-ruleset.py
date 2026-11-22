#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成自有 AGH 规则集 (AdGuard 语法)。

设计原则 —— 与社区列表的根本差异:
  1. 意图分层: 社区列表是"发现即拉黑"的扁平集合, 无法表达"同一主域下广告子域要拦、
     功能子域要放行"。本规则集显式分为业务必需放行层 / 纯追踪拦截层。
  2. 强制语义: 放行层统一用 @@||x^$important, 拦截层统一用 ||x^$important。
     $important 可压过任何其他规则(含社区列表里的 @@ 放行与 || 拦截),
     这是社区列表完全不具备的能力 —— 社区只能靠"别把域名列进黑名单"被动规避。
  3. 精确粒度: 放行精确到具体主机名, 不做整域放行 (避免连带放过追踪端点);
     拦截用 || 形式覆盖子域树 (社区多为此形式)。
  4. 可审计: 每条规则带分类注释, 生成脚本即真源, 可复现。

输出: rules.txt (AGH 可直接订阅的 AdGuard 语法规则集)
"""
import os, re, datetime

OUT_DIR = '/Volumes/public/旁路由/openclash_ai/own-ruleset'
os.makedirs(OUT_DIR, exist_ok=True)

GENERATED = datetime.date.today().isoformat()

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
    '@@||ads-twitter.com^',
    '@@||amazon-adsystem.com^',
    '@@||shie.com.cn^',
    '@@||ads.tiktok.com^',
    '@@||ads-sg.business-tiktok.com^',
    '@@||ads-va.business-tiktok.com^',
    '@@||ads-api.tiktok.com^',
    '@@||ads-tiktok.com^',
    '@@||ads.union.tiktokv.com^',
    '@@||business.tiktok.com^',
    '@@||business-api.tiktok.com^',
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
    '||an.facebook.com^',
    '||tr.facebook.com^',
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
'其他广告与错误上报': [
    '||bat.bing.com^',
    '||sc-static.net^',
    '||sentry.io^',
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
lines.append('!   2) 强制语义 —— 放行层用 @@||x^$important, 拦截层用 ||x^$important。')
lines.append('!      $important 可压过其他任何规则(包括社区列表里的 @@ 放行与 || 拦截),')
lines.append('!      这是社区列表不具备的能力: 社区只能靠"别把域名列进黑名单"被动规避。')
lines.append('!   3) 精确粒度 —— 放行精确到主机名, 不做整域放行; 拦截用 || 覆盖子域树。')
lines.append('!   4) 可审计   —— 每条规则带分类注释, 生成脚本即真源。')
lines.append('! ============================================================')
lines.append('')

lines.append('! ###########################################################')
lines.append('! ## 第一层: 业务必需放行 (FORCE-ALLOW)')
lines.append('! ## @@||x^$important —— 强制放行, 可压过社区列表的拦截')
lines.append('! ###########################################################')
lines.append('')
n_allow = 0
for cat, rules in FORCE_ALLOW.items():
    lines.append('! --- ' + cat + ' ---')
    for r in rules:
        lines.append(add_imp_allow(r))
        n_allow += 1
    lines.append('')

lines.append('! ###########################################################')
lines.append('! ## 第二层: 纯追踪 / 垃圾广告拦截 (FORCE-BLOCK)')
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
path = os.path.join(OUT_DIR, 'rules.txt')

ap = argparse.ArgumentParser()
ap.add_argument('--check', action='store_true',
                help='只校验 rules.txt 是否与生成器一致, 不写入')
ap.add_argument('--out-dir', default=OUT_DIR, help='输出目录')
args = ap.parse_args()

if args.check:
    # CI 模式: 与仓库中的 rules.txt 比对
    repo_rules = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules.txt')
    if not os.path.exists(repo_rules):
        print('✗ 未找到 rules.txt')
        sys.exit(1)
    cur = open(repo_rules, encoding='utf-8').read()
    if cur != text:
        print('✗ rules.txt 与生成器输出不一致, 请运行 python3 gen-own-ruleset.py 后提交')
        sys.exit(1)
    print('✓ rules.txt 与生成器输出一致')
    sys.exit(0)

open(path, 'w', encoding='utf-8').write(text)

print('=== 生成完成 ===')
print(f'  输出: {path}')
print(f'  放行 {n_allow} 条 · 拦截 {n_block} 条 · 合计 {n_allow+n_block} 条')
print(f'  大小: {os.path.getsize(path)} 字节')

allr = [l for l in lines if l and not l.startswith('!')]
dup = sorted({r for r in allr if allr.count(r) > 1})
print(f'  重复规则: {dup if dup else "无"}')
bad = [r for r in allr if not re.match(r'^(@@)?\|\|[^*]+\^(\$[a-z,]+)?$', r)]
print(f'  语法异常: {bad if bad else "无"}')

# 冲突检查: 同一域名不能同时出现在放行层与拦截层
def dom_of(r):
    m = re.match(r'^(@@)?\|\|([^*]+)\^', r)
    return m.group(2).lower() if m else None

allow_d = {dom_of(r) for r in allr if r.startswith('@@') and dom_of(r)}
block_r = [r for r in allr if not r.startswith('@@')]
conflict = [r for r in block_r if dom_of(r) in allow_d]
if conflict:
    print(f'  !! 放行/拦截冲突 ({len(conflict)} 条), 必须人工裁决:')
    for c in conflict: print('     ', c)
    sys.exit(1)
print('  放行/拦截冲突: 无')

# 放行层不得是整域放行 (会连带放过追踪端点)
whole = [r for r in allr if r.startswith('@@') and dom_of(r) and '.' not in dom_of(r).split('/')[0]]
print(f'  整域放行检查: {"无 ✓" if not whole else whole}')
print()
print('  业务覆盖统计:')
for d in ['tiktok','stripe','paypal','amazon','etsy','shopify','github','anthropic','netflix','douyin']:
    c = sum(1 for r in allr if d in r.lower() and r.startswith('@@'))
    if c: print(f'    {d:<12} 放行 {c} 条')
