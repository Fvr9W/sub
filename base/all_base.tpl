{% if request.target == "clash" or request.target == "clashr" %}

port: {{ default(global.clash.http_port, "7890") }}
socks-port: {{ default(global.clash.socks_port, "7891") }}
allow-lan: {{ default(global.clash.allow_lan, "true") }}
mode: Rule
log-level: {{ default(global.clash.log_level, "info") }}
external-controller: :9090
experimental:
  ignore-resolve-fail: true
clash-for-android:
  ui-subtitle-pattern: '[一-龥]{2,4}'
{% if exists("request.tun") %}
  {% if request.tun == "windows" %}
script:
  engine: expr
  shortcuts:
    bilibilishit: "any(['biliapi', 'bilibili'], host contains #) and any(['-live-tracker-', 'p2p', 'pcdn', 'stun'], host contains #)"
    douyushit: (network == 'udp' or host contains 'p2p') and host contains 'douyu'
    quic: network == 'udp' and dst_port in [443]
    tailscale: network == 'udp' and dst_port in [12345]
    discord_UDP: resolve_process_name() in ['Discord.exe'] and network == 'udp'
    discord_TCP: resolve_process_name() in ['Discord.exe'] and network == 'tcp'
    Download_!=CN: resolve_process_name() in ['DownloadServer.exe', 'IDMan.exe'] and geoip(dst_ip) != 'CN'
    Mail: dst_port in [465, 993, 995] and geoip(dst_ip) != 'CN'
tun:
  enable: true
  stack: gvisor
  dns-hijack:
    - any:53
  auto-route: true
  auto-detect-interface: true
  {% else %}
    {% if request.tun == "open" %}
tun:
  enable: true
  stack: system
  dns-hijack:
    - tcp://any:53
  auto-route: false
  auto-detect-interface: false
    {% else %}
      {% if request.tun == "stash" %}
http:
  # 以 PKCS #12 编码的 CA 证书
  ca: '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'
  # 证书密码
  ca-passphrase: 'FA1A9849'

tun:
  enable: true
  stack: system
  dns-hijack:
    - tcp://any:53
  auto-route: false
  auto-detect-interface: false
      {% else %}
      {% endif %}
    {% endif %}
  {% endif %}
{% endif %}

{% if exists("request.dns") %}
  {% if request.dns == "fake" %}
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  listen: 1053
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
  fallback:
    - https://sm2.doh.pub/dns-query
  fallback-filter:
    geoip: false
    ipcidr:
      - 0.0.0.0/32
  fake-ip-filter:
    - '.lan'
    - '+.local'
    - localhost.ptlogin2.qq.com
    - '+.nip.io'
    ## Windows
    - dns.msftncsi.com
    - www.msftncsi.com
    - www.msftconnecttest.com
    ## onetap
    - '+.onetap.su'
    - '+.onetap.com'
    ## neverlose
    - '+.neverlose.cc'
    - '+.neverlose.com'
    ## EO
    - '+.engineowning.com'
    - '+.engineowning.to'
    ## bgx
    - '+.bgx.gg'
    ## gamesense
    - '+.gamesense.pub'
    ## interwebz
    - '+.interwebz-cheats.com'
    ## aimware
    - '+.aimware.net'
    ## fatality
    - '+.fatality.win'
    ## legendsen
    - '+.legendsen.se'
    ## memesense
    - '+.memesense.gg'
    ## midnight
    - '+.midnight.im'
    ## primordial
    - '+.primordial.gay'
    ## pokerstars
    - '+.ps.im'
  nameserver-policy:
    'raw.githubusercontent.com': '8.8.8.8'
    '+.meiquankongjian.com': '8.8.8.8'
    '+.getxlx.com': '8.8.8.8'
    '+.nachoneko.shop': '8.8.8.8'
    '+.ptrecord.com': '8.8.8.8'
    '+.bing.cn': '1.1.1.1'
    '+.bing.com': '1.1.1.1'
  {% else %}
    {% if request.dns == "host" %}
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  listen: 1053
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
  fallback:
    - https://doh.pub/dns-query
  fallback-filter:
    geoip: false
    ipcidr:
      - 0.0.0.0/32
  fake-ip-filter:
    - '+.*'
  nameserver-policy:
    'raw.githubusercontent.com': '8.8.8.8'
    '+.meiquankongjian.com': '8.8.8.8'
    '+.getxlx.com': '8.8.8.8'
    '+.nachoneko.shop': '8.8.8.8'
    '+.ptrecord.com': '8.8.8.8'
    '+.bing.cn': '1.1.1.1'
    '+.bing.com': '1.1.1.1'
    {% else %}
    {% endif %}
  {% endif %}
{% endif %}


{% if local.clash.new_field_name == "true" %}
proxies: ~
proxy-groups: ~
rules: ~
{% else %}
Proxy: ~
Proxy Group: ~
Rule: ~
{% endif %}

{% endif %}
{% if request.target == "surge" %}

[General]
loglevel = notify
bypass-system = true
skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,localhost,*.local,e.crashlytics.com,captive.apple.com,::ffff:0:0:0:0/1,::ffff:128:0:0:0/1
#DNS设置或根据自己网络情况进行相应设置
bypass-tun = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
dns-server = 119.29.29.29,223.5.5.5

[Script]
http-request https?:\/\/.*\.iqiyi\.com\/.*authcookie= script-path=https://raw.githubusercontent.com/NobyDa/Script/master/iQIYI-DailyBonus/iQIYI.js

{% endif %}
{% if request.target == "loon" %}

[General]
#!date = 2023-12-30 21:27:02
# IPV6 启动与否
ipv6 = false
# udp 类的 dns 服务器，用,隔开多个服务器，system 表示系统 dns
dns-server = 119.29.29.29, 223.5.5.5
# DNS over HTTPS服务器，用,隔开多个服务器
# doh-server = https://223.5.5.5/resolve, https://sm2.doh.pub/dns-query
# 是否开启局域网代理访问
allow-wifi-access = false
# 开启局域网访问后的 http 代理端口
wifi-access-http-port = 7222
# 开启局域网访问后的 socks5 代理端口
wifi-access-socks5-port = 7221
# 测速所用的测试链接，如果策略组没有自定义测试链接就会使用这里配置的
proxy-test-url = http://connectivitycheck.gstatic.com
# 节点测速时的超时秒数
test-timeout = 2
# 指定流量使用哪个网络接口进行转发
interface-mode = auto
sni-sniffing = true
# 禁用 stun 是否禁用 stun 协议的 udp 数据，禁用后可以有效解决 webrtc 的 ip 泄露
disable-stun = true
# 策略改变时候打断连接
disconnect-on-policy-change = true
# 一个节点连接失败几次后会进行节点切换，默认 3 次
switch-node-after-failure-times = 3
# 订阅资源解析器链接
resource-parser = https://gitlab.com/lodepuly/vpn_tool/-/raw/main/Resource/Script/Sub-Store/sub-store-parser_for_loon.js
# 自定义 geoip 数据库的 url
geoip-url = https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.mmdb
# 配置了该参数，那么所配置的这些IP段、域名将不会转发到Loon，而是由系统处理
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com, e.crashlynatics.com
# 配置了该参数，那么所配置的这些IP段、域名就会不交给Loon来处理，系统直接处理
bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 239.255.255.250/32, 255.255.255.255/32
# 当切换到某一特定的WiFi下时改变Loon的流量模式，如"loon-wifi5g":DIRECT，表示在loon-wifi5g这个wifi网络下使用直连模式，"cellular":PROXY，表示在蜂窝网络下使用代理模式，"default":RULE，默认使用分流模式
{% if exists("request.who") %}
  {% if request.who == "self" %}
ssid-trigger = "Cccccc":PROXY,"Cccccc_5G":PROXY,"cellular":RULE,"default":RULE
  {% else %}
    {% if request.who == "lulu" %}
ssid-trigger = "Society-5G":DIRECT,"Society":DIRECT,"cellular":RULE,"default":RULE
    {% else %}
ssid-trigger = "INFINITY-WORLD":DIRECT,"nana":DIRECT,"cellular":RULE,"default":RULE
    {% endif %}
  {% endif %}
{% endif %}

[Proxy]

[Remote Proxy]

[Remote Filter]

[Proxy Group]

Premium=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
Game=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/game.png
Daily=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Daily.png
Blizzard=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
Garena=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
PlayStation=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/PSN.png
Rockstar=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
SteamChina=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
SteamGlobal=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
Ubisoft=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
Xboxlive=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
Microsoft=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
Riot=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/League_of_Legends.png
Hax=select, direct, img-url=https://raw.githubusercontent.com/Fvr9W/sub/master/rules/onetap.png
Other Games=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
B1gProxy=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Global.png
Trading=select, direct, img-url=https://raw.githubusercontent.com/Fvr9W/sub/master/rules/trading.png
Telegram=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Telegram.png
Discord=select, direct, img-url=https://raw.githubusercontent.com/Fvr9W/sub/master/rules/discord.png
Spotify=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Spotify.png
Netflix=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Netflix.png
GlobalMedia=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Streaming.png
GlobalGameDownload=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
PrivateTracker=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
SougouInput=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
Hijacking=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
HK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
FastLHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
CnixHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
AutoHK 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
AutoHK1 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
AutoHK2 🇭🇰=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
TW 🇨🇳=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
AutoTW 🇨🇳=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
KR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
AutoKR 🇰🇷=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
JP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
AutoJP 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
AutoJP1 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
AutoJP2 🇯🇵=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
SGP 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
AutoSGP 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
AutoSG 🇸🇬=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
SEA 🌏=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
AutoSEA 🌏=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
AU 🇦🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
AutoAU 🇦🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
RU 🇷🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
AutoRU 🇷🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
EU 🇪🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
AutoEU 🇪🇺=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
CA 🇨🇦=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
AutoCA 🇨🇦=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
NA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
AutoNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
AutoNA1 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
AutoNA2 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
FastLNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
CnixNA 🇺🇲=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png

ALL=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
NEX=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
TAG=select, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/TAG.png
CNIX=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/CNIX.png
FastL=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Fastlink.png
FREE=select, direct, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Team.png

[Rule]

[Remote Rule]

[Rewrite]

[Host]

[Script]


[Plugin]
# 基础
https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.loon.plugin, policy = B1gProxy, tag = BoxJS, enabled = true
https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/Loon.plugin, policy = B1gProxy, tag = SubStore, enabled = true
https://raw.githubusercontent.com/Script-Hub-Org/Script-Hub/main/modules/script-hub.loon.plugin, policy = B1gProxy, tag = ScriptHub, enabled = true
# 解锁
https://raw.githubusercontent.com/Guding88/Script/main/APPheji_Guding.plugin, tag=「合集2」会员破解, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/Fvr9W/sub/master/rules/Unlock.qxrewrite/_end_/Unlock.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集1」会员破解, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/yqc007/QuantumultX/master/LightBeautyCamCrack.js/_end_/LightBeautyCamCrack.plugin?type=qx-rewrite&target=loon-plugin, tag=「轻颜相机5.2.1」会员破解, enabled = false
https://raw.githubusercontent.com/Keywos/rule/main/loon/TikTok.plugin, policy = GlobalMedia, tag=「TikTok」解锁区域, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/TestFlight.plugin, tag=「TestFlight」解锁区域, policy = DIRECT, enabled = true
https://raw.githubusercontent.com/app2smile/rules/master/plugin/spotify.plugin, tag=「Spotify」解锁, enabled = true
# 功能增强
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/1.1.1.1.plugin, tag=「1.1.1.1」配置管理, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Auto_Join_TF.plugin, policy = DIRECT, tag=「TestFlight」自动加入, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/BingAI.plugin, policy = Microsoft, tag=「BingAI」解锁, enabled = true
https://raw.githubusercontent.com/BiliUniverse/Enhanced/main/modules/BiliBili.Enhanced.plugin, tag=自定义「哔哩哔哩粉白」主界面, enabled = true
https://raw.githubusercontent.com/BiliUniverse/Global/main/modules/BiliBili.Global.plugin, tag=自动化「哔哩哔哩粉白」线路及全区搜索, enabled = true
https://raw.githubusercontent.com/DualSubs/Universal/main/modules/DualSubs.Universal.plugin, tag=「流媒体平台」字幕增强及双语模块, enabled = true
https://raw.githubusercontent.com/DualSubs/YouTube/main/modules/DualSubs.YouTube.plugin, tag=「YouTube」字幕增强及双语模块, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Google.plugin, tag=「Google」重定向, enabled = false
https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/plugin/HTTPDNS.Block.plugin, tag=「HTTPDNS」禁止, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/LoonGallery.plugin, policy = B1gProxy, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Fileball_mount.plugin, tag=「Fileball」挂载增强, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/JD_Price.plugin, tag=「京东」比价脚本, enabled = true
https://raw.githubusercontent.com/VirgilClyne/iRingo/main/plugin/Location.plugin, tag=自定义「定位服务」与「地图」功能, enabled = true
https://raw.githubusercontent.com/VirgilClyne/iRingo/main/plugin/Siri.plugin, tag=自定义「Siri与搜索」功能, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/QuickSearch.plugin, tag=「QuickSearch」增强, enabled = false
https://raw.githubusercontent.com/Keywos/rule/main/loon/Netisp.plugin, tag=「节点」检测, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/WARP_Node_Query.plugin, tag=「WARP」节点查询, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Weixin_external_links_unlock.plugin, tag=「微信」外链增强, enabled = true
# 去广告合集
http://script.hub/file/_start_/https://raw.githubusercontent.com/Fvr9W/sub/master/rules/Remix.snippet/_end_/Remix.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集1」去广告, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/MyBlockAds.conf/_end_/MyBlockAds.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集2」去广告, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/cnftp.snippet/_end_/cnftp.plugin?type=qx-rewrite&target=loon-plugin, tag=「爱奇艺|芒果|腾讯视频|优酷」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Remove_ads_by_keli.plugin, tag=「合集3」去广告, enabled = true
# 去广告单独
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Amap_remove_ads.plugin, tag=「高德地图」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Baidu_input_method_remove_ads.plugin, tag=「百度输入法」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/BaiduNetDisk_remove_ads.plugin, tag=「百度网盘」去广告, enabled = true
https://raw.githubusercontent.com/RuCu6/Loon/main/Plugins/bdmap.plugin, tag=「百度地图」去广告, enabled = true
https://raw.githubusercontent.com/BiliUniverse/ADBlock/main/modules/BiliBili.ADBlock.plugin, tag=「哔哩哔哩粉白」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Cainiao_remove_ads.plugin, tag=「菜鸟裹裹」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Daily_remove_ads.plugin, tag=「剑网3推栏」去广告, enabled = false
https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/Loon/Plugin/FanQieNovel.plugin, tag=「番茄小说」去广告, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Himalaya_remove_ads.plugin, tag=「喜马拉雅」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/IThome_remove_ads.plugin, tag=「IThome」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/NeteaseCloudMusic_remove_ads.plugin, tag=「网易云音乐」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/QiDian_remove_ads.plugin, tag=「起点」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/QQMusic_remove_ads.plugin, tag=「QQ音乐」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/RedPaper_remove_ads.plugin, tag=「小红书」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/smzdm_remove_ads.plugin, tag=「什么值得买」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Tieba_remove_ads.plugin, tag=「百度地图」去广告, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/chouchoui/QuanX/master/Scripts/reddit/reddit.ad.sgmodule/_end_/reddit.plugin?type=surge-module&target=loon-plugin, tag=「红迪」去广告, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/TubeMax_remove_ads.plugin, policy = B1gProxy, tag=「TubeMax」去广告, enabled = false
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Weibo_remove_ads.plugin, tag=「微博国内版」去广告, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Weibo.conf/_end_/WeiBoWorldWide.plugin?type=qx-rewrite&target=loon-plugin, tag=「微博国际版」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/Weixin_Official_Accounts_remove_ads.plugin, tag=「微信公众号」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/WexinMiniPrograms_Remove_ads.plugin, tag=「部分微信小程序」去广告, enabled = true
https://gitlab.com/lodepuly/vpn_tool/-/raw/master/Tool/Loon/Plugin/YouTube_remove_ads.plugin, tag=「YouTube」去广告, enabled = true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/zheye/zheye.lnplugin, tag=「知乎」去广告, enabled = true
# 签到
https://raw.githubusercontent.com/ClydeTime/BiliBili/main/modules/BiliBiliDailyBonus.plugin, tag=「哔哩哔哩」签到, enabled = true
http://script.hub/file/_start_/https://raw.githubusercontent.com/Fvr9W/sub/master/rules/GetCookie.conf/_end_/GetCookie.plugin?type=qx-rewrite&target=loon-plugin, tag=「合集」签到CK一体化, enabled = true

[MITM]
hostname = 
{% if exists("request.who") %}
{% if request.who == "self" %}
ca-passphrase = FA1A9849
ca-p12 = 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
{% endif %}
{% if request.who == "lulu" %}
ca-passphrase = DlerCloud
ca-p12 = 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
{% endif %}
{% if request.who == "tira" %}
ca-passphrase = 1852F97B
ca-p12 = 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
{% endif %}
{% if request.who == "xty" %}
ca-passphrase = 64313C61
ca-p12 = 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
{% endif %}
{% if request.who == "biu" %}
ca-passphrase = FC13F6A1
ca-p12 = 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
{% endif %}
{% if request.who == "leo" %}
ca-passphrase = DlerCloud
ca-p12 = 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
{% endif %}
{% else %}
passphrase = DlerCloud
ca-p12 = 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
{% endif %}
skip-server-cert-verify = false
{% endif %}

{% if request.target == "quan" %}

[SERVER]

[SOURCE]

[BACKUP-SERVER]

[SUSPEND-SSID]

[POLICY]

[DNS]
1.1.1.1

[REWRITE]

[URL-REJECTION]

[TCP]

[GLOBAL]

[HOST]

[STATE]
STATE,AUTO

[MITM]

{% endif %}


{# 
Target : Quantumult X
Request: who (self, lulu, tira, xty, biu, leo, none)
         tf (true, false)
#}
{% if request.target == "quanx" %}
[general]
#!date = 2023-10-15 03:18:05
network_check_url=http://www.baidu.com
server_check_url=http://connectivitycheck.gstatic.com
excluded_routes=192.168.0.0/16, 193.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8
dns_exclusion_list = +.lan, +.local, localhost.ptlogin2.qq.com, +.nip.io
resource_parser_url= https://fastly.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/resource-parser.js
geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/IP_API.js

# 指定在某个 Wi-Fi 下暂停 Quantumult X
{% if exists("request.who") %}
  {% if request.who == "self" %}
running_mode_trigger=filter, filter, Cccccc:all_proxy, zxcvawer:all_proxy, Cccccc_5G:all_proxy
  {% else %}
    {% if request.who == "lulu" %}
running_mode_trigger=filter, filter, Society-5G:all_direct, Society:all_direct
    {% else %}
running_mode_trigger=filter, filter, INFINITY-WORLD:all_direct, nana:all_direct
    {% endif %}
  {% endif %}
{% endif %}

[dns]
no-system
no-ipv6
server=223.5.5.5
server=119.29.29.29

[policy]
static=Premium, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
static=Game, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/game.png
static=Daily, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Daily.png
static=Blizzard, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Garena, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=PlayStation, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/PSN.png
static=Rockstar, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=SteamChina, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
static=SteamGlobal, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/steam.png
static=Ubisoft, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Xboxlive, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
static=Microsoft, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Microsoft.png
static=Riot, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/League_of_Legends.png
static=Hax, img-url=https://raw.githubusercontent.com/Fvr9W/sub/master/rules/onetap.png
static=Other Games, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=B1gProxy, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Global.png
static=Trading, img-url=https://raw.githubusercontent.com/Fvr9W/sub/master/rules/trading.png
static=Telegram, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Telegram.png
static=Discord, img-url=https://raw.githubusercontent.com/Fvr9W/sub/master/rules/discord.png
static=Spotify, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Spotify.png
static=Netflix, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Netflix.png
static=GlobalMedia, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Streaming.png
static=GlobalGameDownload, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=PrivateTracker, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=SougouInput, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
static=Hijacking, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
static=HK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=FastLHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=CnixHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=AutoHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=TW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=AutoTW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=KR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=AutoKR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=JP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=AutoJP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=SGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoSGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoSG 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=SEA 🌏, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AutoSEA 🌏, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AU 🇦🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=AutoAU 🇦🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/IPLC.png
static=RU 🇷🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
static=AutoRU 🇷🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Russia.png
static=EU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=AutoEU 🇪🇺, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/EU.png
static=CA 🇨🇦, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
static=AutoCA 🇨🇦, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Canada.png
static=NA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=AutoNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=FastLNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png
static=CnixNA 🇺🇲, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/United_States.png

static=NEX, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Nex.png
static=TAG, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/TAG.png
static=CNIX, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/CNIX.png
static=FastL, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Fastlink.png
static=FREE, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Team.png

[server_remote]

[filter_remote]

[rewrite_remote]
https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf, tag = BoxJS, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/QX.snippet, tag = SubStore, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/snippet/HTTPDNS.Block.snippet, tag=「HTTPDNS」禁止, update-interval=172800, opt-parser=false, enabled=false
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/TikTok.conf, tag = 「TikTok」美区, update-interval=172800, opt-parser=false, enabled=true
# VIP解锁
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/Unlock.qxrewrite, tag=「合集1」VIP解锁, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/Guding88/Script/main/APPheji_Guding.sgmodule, tag=「合集2」VIP解锁, update-interval=86400, opt-parser=true, enabled=true
https://raw.githubusercontent.com/yqc007/QuantumultX/master/LightBeautyCamCrack.js, tag=「轻颜相机5.2.1」VIP解锁, update-interval=86400, opt-parser=true, enabled=true
# 功能增强
https://raw.githubusercontent.com/Orz-3/QuantumultX/master/JD_TB_price.conf, tag=「京东|淘宝」比价脚本, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/Orz-3/QuantumultX/master/Netflix_ratings.conf, tag=「Netflix」评分, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zZPiglet/Task/master/zhihu.conf, tag=「知乎」不跳转, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zZPiglet/Task/master/UnblockURLinWeChat.conf, tag=「微信」链接助手, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/DualSubs/Universal/main/modules/DualSubs.Universal.snippet, tag=「流媒体平台」字幕增强及双语模块, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/DualSubs/YouTube/main/modules/DualSubs.YouTube.snippet, tag=「YouTube」字幕增强及双语模块, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/VirgilClyne/iRingo/main/snippet/Siri.snippet, tag=自定义「Siri与搜索」功能, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/VirgilClyne/iRingo/main/snippet/Location.snippet, tag=自定义「定位服务」与「地图」功能, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/BiliUniverse/Enhanced/main/modules/BiliBili.Enhanced.snippet, tag=自定义「哔哩哔哩粉白」主界面, update-interval=172800, opt-parser=false, enabled=true
# 去广告
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/MyBlockAds.conf, tag=「合集1」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/Remix.snippet, tag=「合集2」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/cnftp.snippet, tag=「爱奇艺|芒果|腾讯视频|优酷」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/amap.snippet, tag=「高德地图」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/bdmap.snippet, tag=「百度地图」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/BiliUniverse/ADBlock/main/modules/BiliBili.ADBlock.snippet, tag=「哔哩哔哩粉白」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/cainiao.snippet, tag=「菜鸟裹裹」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/cloudmusic.snippet, tag=「网易云」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/QuantumultX/rewrite/FanQieNovel.qxrewrite, tag=「番茄小说」去广告, update-interval=172800, opt-parser=false, enabled=false
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/KeepStyle.conf, tag=「KEEP」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/qidian.conf, tag=「起点」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/tieba-qx.conf, tag=「贴吧」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/chouchoui/QuanX/master/Scripts/reddit/reddit.ad.snippet, tag=「红迪」去广告, update-interval=172800, opt-parser=false, enabled=false
https://raw.githubusercontent.com/app2smile/rules/master/module/vgtime.conf, tag=「vgTime」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/ithome.snippet, tag=「ithome」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/kuwo.snippet, tag=「酷我」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/smzdm/smzdm_remove_ads.qxrewrite, tag=「什么值得买」去广告, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Applet.conf, tag=「微信某些小程序」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeChat.conf, tag=「微信公众号」去广告, update-interval=172800, opt-parser=false, enabled=false
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Weibo.conf, tag=「微博国际版」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/weibo.snippet, tag=「微博国内版」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/xiaohongshu.snippet, tag=「小红书」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Ximalaya.conf, tag=「喜马拉雅」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/youtube.snippet, tag=「油管」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/zhihu.snippet, tag=「知乎1」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/zheye/zheye.snippet, tag=「知乎2」去广告, update-interval=172800, opt-parser=false, enabled=true
# 去广告收尾
https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/WebPage.conf, tag=「一些网页」去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/adsense.conf, tag=去广告联盟, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/DivineEngine/Profiles/master/Quantumult/Rewrite/General.conf, tag=神机重定向, update-interval=172800, opt-parser=false, enabled=true
# Cookie
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/GetCookie.conf, tag = GetCookie1, update-interval=172800, opt-parser=true, enabled = true
https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/rewrite/cookies.snippet, tag = GetCookie2, update-interval=172800, opt-parser=false, enabled = false

[server_local]

[task_local]
# UI 交互检测
event-interaction https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/streaming-ui-check.js, tag=流媒体 - 解锁查询, img-url=checkmark.seal.system, enabled=true
event-interaction https://raw.githubusercontent.com/I-am-R-E/Functional-Store-Hub/Master/NodeLinkCheck/Script/NodeLinkCheck.js, tag=Env代理链路检测, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Stack.png, enabled=true

# 10000  (By @chavyleung)
42 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10000/10000.js, tag=10000, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/10000.png,enabled=true

# 10010  (By @chavyleung)
43 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10010/10010.js, tag=10010, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/10010.png,enabled=true

# 12123  (By @dompling)


# 爱思助手  (By @Crazy-Z7)
45 9 * * * https://raw.githubusercontent.com/Crazy-Z7/Task/main/Aisisign.js, tag=爱思助手全能版,img-url=https://raw.githubusercontent.com/Crazy-Z7/Task/main/Image/IMG_0917.jpeg,enabled=true

# 百度贴吧  (By @chavyleung)
# 浏览器访问一下: https://tieba.baidu.com 或者 https://tieba.baidu.com/index/
20 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/tieba/tieba.js, tag=百度贴吧, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/tieba.png, enabled=true

# B站每日等级任务  (By @ClydeTime)
46 9 * * * https://raw.githubusercontent.com/ClydeTime/BiliBili/main/js/BiliBiliDailyBonus.js, tag=B站每日等级任务, img-url=https://raw.githubusercontent.com/HuiDoY/Icon/main/mini/Color/bilibili.png, enabled=true

# 霸王茶姬  (By @Guding88)
# 进入微信霸王茶姬小程序 --> 积分商城 --> 积分签到 --> 签到
47 9 * * * https://raw.githubusercontent.com/Guding88/Script/main/bawangchaji/bwcj.js, tag=霸王茶姬小程序签到, img-url=https://raw.githubusercontent.com/Guding88/Script/main/bawangchaji/bwcj.png, enabled=true

# 机场签到  (By @evilbutcher)
# 教程：https://github.com/evilbutcher/QuantumultX/blob/main/check_in/glados/checkin.jpeg
46 9 * * * https://raw.githubusercontent.com/evilbutcher/Quantumult_X/master/check_in/glados/checkincookie_env.js, tag=机场签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/CNIX.png, enabled=true

# 多看阅读  (By @chavyleung)
# `我的` > `签到任务` 等到提示获取 Cookie 成功即可
25 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/duokan/duokan.js, tag=多看, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/duokan.png,enabled=true

# 飞客茶馆  (By @chavyleung)
# 打开 APP, 访问下`个人中心`
45 9 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/flyertea/flyertea.js, tag=飞客茶馆, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/flyertea.png,enabled=true

# 途虎养车  (By @Crazy-Z7)
# 公众号：搜索途虎小程序登录
40 9 * * * https://raw.githubusercontent.com/Crazy-Z7/Task/main/Tuhyche.js, tag=途虎养车积分签到, img-url=https://raw.githubusercontent.com/Crazy-Z7/Task/main/Image/IMG_0905.jpeg, enabled=true

# 什么值得买  (By @blackmatrix7)
# 打开什么值得买APP，点击“我的”，进入右上角的签到页面，等待脚本弹出获取Cookie成功的通知即可。
41 9 * * * https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/smzdm/smzdm_daily.js, tag=什么值得买每日签到, img-url=https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/icon/task/smzdm.png, enabled=true

# 青龙 docker 每日自动同步 boxjs cookie  (By @dompling)
4 0 * * * https://raw.githubusercontent.com/dompling/Script/master/jd/ql_cookie_sync.js, tag=青龙同步, img-url=https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/magicjs/images/qinglong.png, enabled=true

# 起点  (By @MCdasheng)
20 21 * * * https://raw.githubusercontent.com/MCdasheng/QuantumultX/main/Scripts/myScripts/qidian/qidian.js, img-url=https://raw.githubusercontent.com/chxm1023/Script_X/main/icon/qidian.png, tag=起点读书, enabled=true

# i茅台自动预约  (By @FoKit)
17 9 * * * https://raw.githubusercontent.com/FoKit/Scripts/main/scripts/i-maotai.js, tag=i茅台自动预约, img-url=https://is1-ssl.mzstatic.com/image/thumb/Purple116/v4/ae/f4/18/aef41811-955e-e6b0-5d23-6763c2eef1ab/AppIcon-0-0-1x_U007emarketing-0-0-0-7-0-0-sRGB-0-0-0-GLES2_U002c0-512MB-85-220-0-0.png/144x144.png, enabled=true

[http_backend]

[filter_local]
Final, Other Game

[rewrite_local]

[mitm]
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
DIRECT, builtin, freedom, domainStrategy=UseIP
REJECT, builtin, blackhole
Dns-Out, builtin, dns

[Routing]
domainStrategy = IPIfNonMatch

[Dns]
hijack = Dns-Out
clientIp = 114.114.114.114

[DnsServer]
localhost
223.5.5.5
8.8.8.8, 53, Remote
8.8.4.4

[DnsRule]
DOMAIN-KEYWORD, geosite:geolocation-!cn, Remote
DOMAIN-SUFFIX, google.com, Remote

[DnsHost]
doubleclick.net = 127.0.0.1

[Log]
loglevel = warning

{% endif %}
{% if request.target == "surfboard" %}

[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
{% endif %}
{% if request.target == "sssub" %}
{
  "route": "bypass-lan-china",
  "remote_dns": "dns.google",
  "ipv6": false,
  "metered": false,
  "proxy_apps": {
    "enabled": false,
    "bypass": true,
    "android_list": [
      "com.eg.android.AlipayGphone",
      "com.wudaokou.hippo",
      "com.zhihu.android"
    ]
  },
  "udpdns": false
}

{% endif %}
