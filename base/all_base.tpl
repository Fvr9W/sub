{# 
Target : Clash, ClashR
Request: dns (fake, tun, none)
         new_name (true, false)
         interface (none, wlan, other)
#}
{% if request.target == "clash" or request.target == "clashr" %}
port: 7890
socks-port: 7891
redir-port: 7892
allow-lan: true
mode: Rule
log-level: info
external-controller: 0.0.0.0:9090
dns:
  enable: true
  ipv6: false
{% if exists("request.dns") %}
{% if request.dns == "fake" %}
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - 'localhost.ptlogin2.qq.com'
    - 'dns.msftncsi.com'
    - 'www.msftncsi.com'
    - 'www.msftconnecttest.com'
    - '*.*.*.*.srv.nintendo.net'
    - '*.*.*.stun.playstation.net'
    - 'xbox.*.microsoft.com'
    - '*.*.*.xboxlive.com'
{% endif %}
{% if request.dns == "tun" %}
  listen: 0.0.0.0:53
  enhanced-mode: redir-host
  hosts:
    'ip.jb.tn': 127.0.0.1
    'p33-smtp.mail.icloud.com.cn': 17.56.8.137
    'p33-imap.mail.icloud.com.cn': 17.56.9.15
{% endif %}
{% else %}
  listen: 0.0.0.0:53
  enhanced-mode: redir-host
  hosts:
    'ip.jb.tn': 127.0.0.1
{% endif %}
  nameserver:
    - 1.2.4.8
    - 119.29.29.29
    - https://dns.alidns.com/dns-query
  fallback:
    - https://dns.google/dns-query
    - tls://1.1.1.1:853
    - https://1.1.1.1/dns-query
    - tls://8.8.8.8:853
  fallback-filter:
    geoip: true
    ipcidr:
      - 240.0.0.0/4
{% if exists("request.interface") %}
{% if request.interface == "none" %}
{% endif %}
{% if request.interface == "wlan" %}
{% endif %}
{% else %}
{% endif %}
{% if request.new_name == "true" %}
proxies: ~
proxy-groups: ~
rules: ~
{% else %}
Proxy: ~
Proxy Group: ~
Rule: ~
{% endif %}
{% endif %}

{# 
Target : Quantumult X
Request: who (self, lulu, tira, xty, biu, leo, none)
         tf (true, false)
#}
{% if request.target == "quanx" %}
[general]
network_check_url=http://bing.com/
server_check_url=http://cp.cloudflare.com/generate_204
excluded_routes=192.168.0.0/16, 193.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8
dns_exclusion_list = *.cmpassport.com,  *.jegotrip.com.cn, *.icitymobile.mobi, id6.me, *.pingan.com.cn, *.cmbchina.com, *.abchina.com
geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/IP_API.js
# 指定在某个 Wi-Fi 下暂停 Quantumult X
{% if exists("request.who") %}
  {% if request.who == "self" %}
    running_mode_trigger=filter, filter, Cccccc:all_direct, zxcvawer:all_direct
  {% else %}
    {% if request.who == "lulu" %}
      running_mode_trigger=filter, filter, Society-5G:all_direct, Society:all_direct
    {% else %}
      ;ssid_suspended_list=LINK_22E174, LINK_22E175
    {% endif %}
  {% endif %}
{% endif %}

[dns]
server=1.2.4.8
server=119.29.29.29
server=223.5.5.5
server=8.8.8.8
server=1.1.1.1
server=/*.taobao.com/223.5.5.5
server=/*.tmall.com/223.5.5.5
server=/*.alipay.com/223.5.5.5
server=/*.alicdn.com/223.5.5.5
server=/*.aliyun.com/223.5.5.5
server=/*.jd.com/119.28.28.28
server=/*.qq.com/119.28.28.28
server=/*.tencent.com/119.28.28.28
server=/*.weixin.com/119.28.28.28
server=/*.bilibili.com/119.29.29.29
server=/dida365.com/119.29.29.29
server=/*.dida365.com/119.29.29.29
server=/hdslb.com/119.29.29.29
server=/*.163.com/119.29.29.29
server=/*.126.com/119.29.29.29
server=/*.126.net/119.29.29.29
server=/*.127.net/119.29.29.29
server=/*.netease.com/119.29.29.29
server=/*.mi.com/119.29.29.29
server=/*.xiaomi.com/119.29.29.29
server=/*.discordapp.com/8.8.4.4
server=/*.discord.media/8.8.4.4
server=/*.discord.gg/8.8.4.4
server=/*.google.com/8.8.8.8
server=/*.twitter.com/8.8.8.8
{% if exists("request.who") %}
{% if request.who == "self" %}
server=192.168.123.1
{% else %}
{% endif %}
{% endif %}

[policy]
static=Premium, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/NyanCat.png
static=Game, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=N3RO, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/N3RO.png
static=Daily, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Daily.png
static=Call of Duty, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=League of Legends(garena), img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=GTA V or RDR2(Rockstar), img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=GranTurismo, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=R6 Rainbow Six Siege(ubisoft), img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Sea of Thieves(XboxLive), img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Steam Community, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Onetap, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Skeet, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=TeamViewer, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Other Games, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=B1gProxy, img-url=img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Proxy.png
static=Telegram, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Telegram.png
static=Netflix, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Netflix.png
static=GlobalMedia, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/GlobalMedia.png
static=GlobalGameDownload, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=Hijacking, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hijacking.png
static=AutoHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=SelectHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=AutoTW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=SelectTW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=AutoKR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=SelectKR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=AutoJP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=SelectJP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=AutoSGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=SelectSGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoSEA 🌏, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=SelectSEA 🌏, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AutoAU 🇦🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=SelectAU 🇦🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AutoRU 🇷🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
static=SelectRU 🇷🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
static=AutoEU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=SelectEU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=AutoCA 🇨🇦, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
static=SelectCA 🇨🇦, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
static=AutoNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=SelectNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=LowRateHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=AutoLowRate 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=FallbackLowRate 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=LowRateTW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=AutoLowRate 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=FallbackLowRate 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=LowRateKR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=AutoLowRate 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=FallbackLowRate 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=LowRateJP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=AutoLowRate 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=FallbackLowRate 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=LowRateSGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoLowRate 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=FallbackLowRate 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=LowRateEU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=AutoLowRate 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=FallbackLowRate 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=LowRateNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=AutoLowRate 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=FallbackLowRate 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png

[server_remote]

[filter_remote]

[rewrite_remote]
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/TikTok.conf, tag = TikTok, enabled = true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/QuantumultX/Advertising/Advertising.conf, tag = 去广告1, enabled = true
https://raw.githubusercontent.com/NobyDa/Script/master/QuantumultX/Js.conf, tag = NobyDaJS, enabled = true
https://subweb.oss-cn-hongkong.aliyuncs.com/Module/embyUnlocked.conf, tag = emby破解, enabled = false
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/startup/startup.qxrewrite, tag=开屏去广告, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/zhihu/zhihu_plus.qxrewrite, tag=知乎助手_去广告及体验增强, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/bilibili/bilibili_plus.qxrewrite, tag=哔哩哔哩_去广告, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/eleme/eleme_daily.qxrewrite, tag=饿了么_获取Cookie, enabled = false
https://raw.githubusercontent.com/nzw9314/QuantumultX/master/Get_Cookie_Remote.conf, tag = 获取Cookie, enabled = false

[server_local]

[task_local]
# 52破解
# 浏览器访问https://www.52pojie.cn/home.php?mod=space 即可
2 0 * * * https://raw.githubusercontent.com/NobyDa/Script/master/52pojie-DailyBonus/52pojie.js, tag=52破解, img-url=https://raw.githubusercontent.com/Orz-3/task/master/52pj.png,enabled=true

# bilibili
# 打开浏览器访问: https://www.bilibili.com 或 https://live.bilibili.com
2 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/bilibili/bilibili.js, tag=bilibili, img-url=https://raw.githubusercontent.com/Orz-3/task/master/bilibili.png,enabled=true

# 百度贴吧
# 打开App,访问下右下角 `我的
1,2,3 0 * * * https://raw.githubusercontent.com/NobyDa/Script/master/BDTieBa-DailyBonus/TieBa.js, tag=贴吧, img-url=https://raw.githubusercontent.com/Orz-3/task/master/tieba.png,enabled=true

# 滴滴出行  (By @zZPiglet)
# 进入"滴滴出行"，若弹出"首次写入滴滴出行 Token 成功"
1 0 * * * https://raw.githubusercontent.com/zZPiglet/Task/master/DiDi/DiDi.js, tag=滴滴出行, img-url=https://raw.githubusercontent.com/Orz-3/task/master/didi.png,enabled=true
59 23 * * * https://raw.githubusercontent.com/zZPiglet/Task/master/DiDi/DiDi_reward.js, tag=滴滴出行, img-url=https://raw.githubusercontent.com/Orz-3/task/master/didi.png,enabled=true

# 饿了么   (By @syzzzf)
# 打开 APP, 访问下`我的`>`签到领红包`(左上角)
10 00 * * * https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/eleme/eleme_daily.js, tag=饿了么_领取吃货豆, enabled=true
00 10 * * * https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/eleme/eleme_mission.js, tag=饿了么_领取会员任务, enabled=true

# 中国联通
#1打开 APP , 进入签到页面, 系统提示: `获取刷新链接: 成功`,然后手动签到 1 次
#2首页>天天抽奖, 系统提示 `2` 次: `获取Cookie: 成功 (登录抽奖)` 和 `获取Cookie: 成功 (抽奖次数)`
8 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10010/10010.js, tag=中国联通, img-url=https://raw.githubusercontent.com/Orz-3/task/master/10010.png,enabled=true

# 电信营业厅
# 打开 APP 手动签到一次: 访问下右下角 `我` > `签到` (头像下面)
1 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10000/10000.js, tag=电信营业厅, img-url=https://raw.githubusercontent.com/Orz-3/task/master/10000.png,enabled=true

# 什么值得买
# 浏览器访问并登录: https://zhiyou.smzdm.com/user/login
5 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/smzdm/quanx/smzdm.js, tag=什么值得买, img-url=https://raw.githubusercontent.com/Orz-3/task/master/smzdm.png,enabled=true

# 多看阅读
# `我的` > `签到任务` 等到提示获取 Cookie 成功即可
13 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/duokan/duokan.js, tag=多看, img-url=https://raw.githubusercontent.com/Orz-3/task/master/duokan.png,enabled=true

# 中国联通
# 1打开 APP , 进入签到页面, 系统提示: `获取刷新链接: 成功`,然后手动签到 1 次
# 2首页>天天抽奖, 系统提示 `2` 次: `获取Cookie: 成功 (登录抽奖)` 和 `获取Cookie: 成功 (抽奖次数)`
8 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10010/10010.js, tag=中国联通, img-url=https://raw.githubusercontent.com/Orz-3/task/master/10010.png,enabled=true

# > 万达电影
10 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/wanda/wanda.js, tag=wanda-签到, img-url=https://raw.githubusercontent.com/Orz-3/task/master/wanda.png,enabled=true

# TestFlight公测监控 (By @syzzzf)
0 0-23/1 * * * https://raw.githubusercontent.com/songyangzz/QuantumultX/master/testflight.js, tag=TestFlight公测监控, img-url=https://raw.githubusercontent.com/Orz-3/task/master/testflight.png,enabled=false

# 飞客茶馆
# 打开 APP, 访问下`个人中心`
3 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/flyertea/flyertea.js, tag=飞客茶馆, img-url=https://raw.githubusercontent.com/Orz-3/task/master/flyertea.png,enabled=true

# > 机场签到 (by evilbutcher & Neurogram )
# 使用BoxJs配置订阅及密码
58 23 * * * https://raw.githubusercontent.com/evilbutcher/Quantumult_X/master/check_in/glados/checkin_env.js, tag=机场签到, img-url=https://raw.githubusercontent.com/Orz-3/task/master/airport.png,enabled=true

# > 京东多合一签到
5 0 * * * https://raw.githubusercontent.com/NobyDa/Script/master/JD-DailyBonus/JD_DailyBonus.js, tag=京东多合一签到, img-url=https://raw.githubusercontent.com/Orz-3/task/master/jd.png,enabled=true

[filter_local]
ip-cidr, 10.0.0.0/8, direct
ip-cidr, 127.0.0.0/8, direct
ip-cidr, 172.16.0.0/12, direct
ip-cidr, 192.168.0.0/16, direct
ip-cidr, 224.0.0.0/24, direct
# 知乎去广告
# 将以下两条规则，必须置于filter_local中的最上方
IP-CIDR,118.89.204.198/32,REJECT
IP6-CIDR,2402:4e00:1200:ed00:0:9089:6dac:96b6/128,REJECT
# 以下规则，位置越靠前越好
HOST,118.89.204.198,REJECT
HOST,mqtt.zhihu.com,reject
HOST,sugar.zhihu.com,reject
HOST,appcloud2.in.zhihu.com,REJECT
USER-AGENT,AVOS*,REJECT
# 分界线
geoip, cn, direct
final, Final

[rewrite_local]

[mitm]
hostname = www.zhihu.com,api.m.jd.com
{% if exists("request.who") %}
{% if request.who == "self" %}
passphrase = FA1A9849
p12 = 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
{% endif %}
{% if request.who == "lulu" %}
passphrase = DlerCloud
p12 = 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
{% endif %}
{% if request.who == "tira" %}
passphrase = 1852F97B
p12 = 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
{% endif %}
{% if request.who == "xty" %}
passphrase = 64313C61
p12 = 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
{% endif %}
{% if request.who == "biu" %}
passphrase = FC13F6A1
p12 = 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
{% endif %}
{% if request.who == "leo" %}
passphrase = DlerCloud
p12 = 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
{% endif %}
{% else %}
passphrase = DlerCloud
p12 = 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
{% endif %}
{% endif %}


{% if request.target == "mellow" %}
[Endpoint]
Direct, builtin, freedom, domainStrategy=UseIP
Reject, builtin, blackhole
Dns-Out, builtin, dns
Http-Out, builtin, http, address=127.0.0.1, port=7890
Socks-Out, builtin, socks, address=127.0.0.1, port=7891

[Routing]
domainStrategy = IPIfNonMatch

[RoutingRule]
; type, filter, endpoint tag or enpoint group tag
; DNS
IP-CIDR, 223.5.5.5/32, Direct
IP-CIDR, 8.8.8.8/32, B1gProxy
IP-CIDR, 8.8.4.4/32, B1gProxy

[Dns]
; hijack = dns endpoint tag
hijack = Dns-Out
clientIp = 114.114.114.114

[DnsServer]
; address, port, tag
223.5.5.5
8.8.8.8, 53, GoogleDNS
8.8.4.4

[DnsRule]
; type, filter, dns server tag
DOMAIN-KEYWORD, geosite:geolocation-!cn, GoogleDNS
DOMAIN, www.google.com, GoogleDNS
DOMAIN-FULL, www.twitter.com, GoogleDNS
DOMAIN-SUFFIX, google.com, GoogleDNS

[DnsHost]
; domain = ip
localhost = 127.0.0.1

[Log]
loglevel = warning
{% endif %}


{% if request.target == "surfboard" %}
{% endif %}


{% if request.target == "surge" %}
{% endif %}


{% if request.target == "loon" %}
{% endif %}
