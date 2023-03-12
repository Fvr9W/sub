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
    - 114.114.114.114
    - 223.5.5.5
    - 8.8.8.8
  fallback: []
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 0.0.0.0/8
      - 10.0.0.0/8
      - 100.64.0.0/10
      - 127.0.0.0/8
      - 169.254.0.0/16
      - 172.16.0.0/12
      - 192.0.0.0/24
      - 192.0.2.0/24
      - 192.88.99.0/24
      - 192.168.0.0/16
      - 198.18.0.0/15
      - 198.51.100.0/24
      - 203.0.113.0/24
      - 224.0.0.0/4
      - 240.0.0.0/4
      - 255.255.255.255/32
    domain:
      - "+.google.com"
      - "+.facebook.com"
      - "+.youtube.com"
      - "+.githubusercontent.com"
      - "+.googlevideo.com"
      - "+.msftconnecttest.com"
      - "+.msftncsi.com"
      - msftconnecttest.com
      - msftncsi.com
  fake-ip-filter:
    # === LAN ===
    - '*.example'
    - '*.home.arpa'
    - '*.invalid'
    - '*.lan'
    - '*.local'
    - '*.localdomain'
    - '*.localhost'
    - '*.test'
    ## Firefox / Some linux system depends on the DNS resolution result to determine the network availability.
    - 'network-test.debian.org'
    - 'detectportal.firefox.com'
    - 'resolver1.opendns.com'
    ## Twilio's Global Network Traversal Service, reliable STUN and TURN capabilities for WebRTC
    - 'global.turn.twilio.com'
    - 'global.stun.twilio.com'
    ## Firebase Crashlytics
    - 'e.crashlytics.com'
    # === Apple Software Update Service ===
    ## Apple Web Authentication Modern 跨设备验证 本地连接
    - 'cable.auth.com'
    ## Apple 针对使用强制门户的网络进行互联网连接验证
    - 'captive.apple.com'
    - 'mesu.apple.com'
    - 'swscan.apple.com'
    - 'swquery.apple.com'
    - 'swdownload.apple.com'
    - 'swcdn.apple.com'
    - 'swdist.apple.com'
    # === ASUS Router ===
    - '*.router.asus.com'
    # === Google ===
    - 'lens.l.google.com'
    - 'stun.l.google.com'
    ## Golang
    - 'proxy.golang.org'
    # === Linksys Wireless Router ===
    - '*.linksys.com'
    - '*.linksyssmartwifi.com'
    # === Windows 10 Connnect Detection ===
    - '*.ipv6.microsoft.com'
    - '*.msftconnecttest.com'
    - '*.msftncsi.com'
    - 'msftconnecttest.com'
    - 'msftncsi.com'
    # === NTP Service ===
    - 'ntp.*.com'
    - 'ntp1.*.com'
    - 'ntp2.*.com'
    - 'ntp3.*.com'
    - 'ntp4.*.com'
    - 'ntp5.*.com'
    - 'ntp6.*.com'
    - 'ntp7.*.com'
    - 'time.*.apple.com'
    - 'time.*.com'
    - 'time.*.gov'
    - 'time1.*.com'
    - 'time2.*.com'
    - 'time3.*.com'
    - 'time4.*.com'
    - 'time5.*.com'
    - 'time6.*.com'
    - 'time7.*.com'
    - 'time.*.edu.cn'
    - '*.time.edu.cn'
    - '*.ntp.org.cn'
    - '+.pool.ntp.org'
    - 'time1.cloud.tencent.com'
    # === Music Service ===
    ## 咪咕音乐
    - '+.music.migu.cn'
    - 'music.migu.cn'
    ## 太和音乐
    - 'music.taihe.com'
    - 'musicapi.taihe.com'
    ## 酷狗音乐
    - 'songsearch.kugou.com'
    - 'trackercdn.kugou.com'
    - '+.kuwo.cn'
    ## joox音乐
    - 'api-jooxtt.sanook.com'
    - 'api.joox.com'
    - 'joox.com'
    ## 腾讯音乐
    - 'y.qq.com'
    - '+.y.qq.com'
    - 'amobile.music.tc.qq.com'
    - 'aqqmusic.tc.qq.com'
    - 'mobileoc.music.tc.qq.com'
    - 'streamoc.music.tc.qq.com'
    - 'dl.stream.qqmusic.qq.com'
    - 'isure.stream.qqmusic.qq.com'
    ## 网易音乐
    - 'music.163.com'
    - '+.music.163.com'
    - '+.126.net'
    - '+.uu.163.com'
    ## 虾米音乐
    - '*.xiami.com'
    # === Vedio service ===
    ## Netflix
    - '+.nflxvideo.net'
    ## Bilibili
    - '*.mcdn.bilivideo.cn'
    ## Disney Plus
    - '+.media.dssott.com'
    ## shark007 Codecs 
    - 'shark007.net'
    # === Game Service ===
    ## Microsoft Xbox
    - 'speedtest.cros.wr.pvp.net'
    - '*.*.xboxlive.com'
    - 'xbox.*.*.microsoft.com'
    - 'xbox.*.microsoft.com'
    - 'xnotify.xboxlive.com'
    ## Nintendo Switch
    - '*.*.*.srv.nintendo.net'
    - '+.srv.nintendo.net'
    ## Sony PlayStation
    - '*.*.stun.playstation.net'
    - '+.stun.playstation.net'
    ## STUN Server
    - '+.stun.*.*.*.*'
    - '+.stun.*.*.*'
    - '+.stun.*.*'
    - 'stun.*.*.*'
    - 'stun.*.*'
    ## Wotgame
    - '+.battlenet.com.cn'
    - '+.wotgame.cn'
    - '+.wggames.cn'
    - '+.wowsgame.cn'
    - '+.wargaming.net'
    ## 拳头
    - '+.riotgames.com'
    - '+.pvp.net'
    ## 动视暴雪
    - '+.logon.battlenet.com.cn'
    - '+.blzstatic.cn'
    - '+.demonware.net'
    - '+.battle.net'
    - '+.blizzard.com'
    ## FinalFantasy XIV Worldwide Server & CN Server
    - '+.square-enix.com'
    - '+.finalfantasyxiv.com'
    - '+.ffxiv.com'
    - '+.ff14.sdo.com'
    - 'ff.dorado.sdo.com'
    # === Other ===
    ## AD DS
    - 'PDC._msDCS.*.*'
    - 'DC._msDCS.*.*'
    - 'GC._msDCS.*.*'
    ## QQ Quick Login
    - 'localhost.ptlogin2.qq.com'
    - 'localhost.sec.qq.com'
    - 'Mijia Cloud'
    ## 移动认证登录
    - '*.cmpassport.com' 
    ## 电信天翼账号免密登录
    - 'id6.me'
    - 'open.e.189.cn'
    ## 联通沃账号一键登录
    - 'mdn.open.wo.cn'
    - 'opencloud.wostore.cn'
    - 'auth.wosms.cn'
    ## 无忧行
    - '+.jegotrip.com.cn'
    ## 誉隆信息
    - '+.icitymobile.mobi'
    ## 银行
    - '+.pingan.com.cn'
    - '+.cmbchina.com'
    - '+.cmbimg.com'
    - '+.abchina.com'
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
  nameserver-policy:
    'talk.google.com': '108.177.125.188'
    'mtalk.google.com': '108.177.125.188'
    'alt1-mtalk.google.com': '3.3.3.3'
    'alt2-mtalk.google.com': '3.3.3.3'
    'alt3-mtalk.google.com': '74.125.200.188'
    'alt4-mtalk.google.com': '74.125.200.188'
    'alt5-mtalk.google.com': '3.3.3.3'
    'alt6-mtalk.google.com': '3.3.3.3'
    'alt7-mtalk.google.com': '74.125.200.188'
    'alt8-mtalk.google.com': '3.3.3.3'
    'blog.google': '119.29.29.29'
    'googletraveladservices.com': '119.29.29.29'
    'dl.google.com': '119.29.29.29'
    'dl.l.google.com': '119.29.29.29'
    'clientservices.googleapis.com': '119.29.29.29'
    'update.googleapis.com': '119.29.29.29'
    'translate.googleapis.com': '119.29.29.29'
    'fonts.googleapis.com': '119.29.29.29'
    'fonts.gstatic.com': '119.29.29.29'
    'networking.apple': 'https://doh.dns.apple.com/dns-query'
    '+.icloud.com': 'https://doh.dns.apple.com/dns-query'
    '+.google': '8.8.8.8'
    '+.google.com': '8.8.8.8'
    '+.google.com.??': '8.8.8.8'
    '+.gstatic.com': '8.8.8.8'
    '+.ggpht.com': '8.8.8.8'
    '+.googleusercontent.com': '8.8.8.8'
    '+.1e100.net': '8.8.8.8'
    '+.youtube': '8.8.8.8'
    '+.youtube.com': '8.8.8.8'
    '+.ytimg.com': '8.8.8.8'
    '+.googlevideo.com': '8.8.8.8'
    '+.gvt?.com': '8.8.8.8'
    '+.recaptcha.net': '8.8.8.8'
    '+.gmail.com': '8.8.8.8'
    '+.googlesource.com': '8.8.8.8'
    '+.googleadservices.com': '8.8.8.8'
    '+.doubleclick.net': '8.8.8.8'
    '+.adsense.com': '8.8.8.8'
    '+.adsensecustomsearchads.com': '8.8.8.8'
    '+.adsenseformobileapps.com': '8.8.8.8'
    '+.gle': '8.8.8.8'
    'goo.gl': '8.8.8.8'
    '+.cloudflare.com': '1.1.1.1'
    '+.cloudflarestream.com': '1.1.1.1'
    '+.cloudflareclient.com': '1.1.1.1'
    '+.cloudflareinsights.com': '1.1.1.1'
    '+.every1dns.net': '1.1.1.1'
    '+.cloudflare-dns.com': '1.1.1.1'
    '+.workers.dev': '1.1.1.1'
    '+.alibaba.cn': '223.5.5.5'
    '+.alibaba.com.cn': '223.5.5.5'
    '+.china.alibaba.com': '223.5.5.5'
    '+.1688.com': '223.5.5.5'
    '+.taobao.com': '223.5.5.5'
    '+.tbcache.com': '223.5.5.5'
    '+.tmall.com': '223.5.5.5'
    '+.alicdn.com': '223.5.5.5'
    '+.aliyundrive.com': '223.5.5.5'
    '+.aliyun.+': '223.5.5.5'
    '+.aliyuncdn.+': '223.5.5.5'
    '+.aliyunddos????.com': '223.5.5.5'
    '+.aliyuncs.com': '223.5.5.5'
    '+.aliyundunwaf.com': '223.5.5.5'
    '+.aliapp.com': '223.5.5.5'
    '+.aliapp.org': '223.5.5.5'
    '+.alibabausercontent.com': '223.5.5.5'
    '+.mmstat.com': '223.5.5.5'
    'tb.cn': '223.5.5.5'
    '+.alipay.com': '223.5.5.5'
    '+.alipay.com.cn': '223.5.5.5'
    '+.alipaydns.com': '223.5.5.5'
    '+.alipayeshop.com': '223.5.5.5'
    '+.alipaylog.com': '223.5.5.5'
    '+.alipayobjects.com': '223.5.5.5'
    '+.alipay-eco.com': '223.5.5.5'
    '+.tencent.com': '119.29.29.29'
    '+.qcloud.com': '119.29.29.29'
    '+.qcloudcdn.cn': '119.29.29.29'
    '+.qcloudcdn.com': '119.29.29.29'
    '+.qcloudcos.com': '119.29.29.29'
    '+.qcloudimg.com': '119.29.29.29'
    '+.qcloudcjgj.com': '119.29.29.29'
    '+.qcloudwzgj.com': '119.29.29.29'
    '+.qcloudzygj.com': '119.29.29.29'
    '+.myqcloud.com': '119.29.29.29'
    '+.tencent-cloud.net': '119.29.29.29'
    '+.tencentcloud-aiot.com': '119.29.29.29'
    '+.tencentcloudapi.com': '119.29.29.29'
    '+.tencentcloudcr.com': '119.29.29.29'
    '+.tencentcloudmarket.com': '119.29.29.29'
    '+.qq.com': '119.29.29.29'
    '+.qlogo.cn': '119.29.29.29'
    '+.qpic.cn': '119.29.29.29'
    '+.weixin.qq.com': '119.29.29.29'
    '+.wx.qq.com': '119.29.29.29'
    '+.weixin.com': '119.29.29.29'
    '+.weixinbridge.com': '119.29.29.29'
    '+.wechat.com': '119.29.29.29'
    '+.servicewechat.com': '119.29.29.29'
    '+.weiyun.com': '119.29.29.29'
    '+.gtimg.cn': '119.29.29.29'
    '+.idqqimg.com': '119.29.29.29'
    '+.cdn-go.cn': '119.29.29.29'
    '+.smtcdns.com': '119.29.29.29'
    '+.smtcdns.net': '119.29.29.29'
    'url.cn': '119.29.29.29'
    '+.baidu': '180.76.76.76'
    '+.baidu.com': '180.76.76.76'
    '+.bdimg.com': '180.76.76.76'
    '+.bdstatic.com': '180.76.76.76'
    '+.baidupcs.+': '180.76.76.76'
    '+.baiduyuncdn.+': '180.76.76.76'
    '+.baiduyundns.+': '180.76.76.76'
    '+.bdydns.+': '180.76.76.76'
    '+.bdycdn.+': '180.76.76.76'
    '+.bdysite.com': '180.76.76.76'
    '+.bdysites.com': '180.76.76.76'
    '+.baidubce.+': '180.76.76.76'
    '+.bcedns.+': '180.76.76.76'
    '+.bcebos.com': '180.76.76.76'
    '+.bcevod.com': '180.76.76.76'
    '+.bceimg.com': '180.76.76.76'
    '+.bcehost.com': '180.76.76.76'
    '+.bcehosts.com': '180.76.76.76'
    'dwz.cn': '180.76.76.76'
    '+.360.cn': 'https://doh.360.cn/dns-query'
    '+.360safe.com': 'https://doh.360.cn/dns-query'
    '+.360kuai.com': 'https://doh.360.cn/dns-query'
    '+.so.com': 'https://doh.360.cn/dns-query'
    '+.360webcache.com': 'https://doh.360.cn/dns-query'
    '+.qihuapi.com': 'https://doh.360.cn/dns-query'
    '+.qhimg.com': 'https://doh.360.cn/dns-query'
    '+.qhimgs.com': 'https://doh.360.cn/dns-query'
    '+.qhimgs?.com': 'https://doh.360.cn/dns-query'
    '+.qhmsg.com': 'https://doh.360.cn/dns-query'
    '+.qhres.com': 'https://doh.360.cn/dns-query'
    '+.qhres?.com': 'https://doh.360.cn/dns-query'
    '+.dhrest.com': 'https://doh.360.cn/dns-query'
    '+.qhupdate.com': 'https://doh.360.cn/dns-query'
    '+.yunpan.cn': 'https://doh.360.cn/dns-query'
    '+.yunpan.com.cn': 'https://doh.360.cn/dns-query'
    '+.yunpan.com': 'https://doh.360.cn/dns-query'
    'urlqh.cn': 'https://doh.360.cn/dns-query'
    'upos-sz-mirrorali.bilivideo.com': '223.5.5.5'
    'upos-sz-mirrorali?.bilivideo.com': '223.5.5.5'
    'upos-sz-mirrorali??.bilivideo.com': '223.5.5.5'
    'upos-sz-mirrorbos.bilivideo.com': '180.76.76.76'
    'upos-sz-mirrorcos.bilivideo.com': '119.29.29.29'
    'upos-sz-mirrorcos?.bilivideo.com': '119.29.29.29'
    'upos-sz-mirrorcos??.bilivideo.com': '119.29.29.29'
    'upos-sz-upcdnbd??.bilivideo.com': '180.76.76.76'
    'upos-sz-upcdntx.bilivideo.com': '119.29.29.29'
    '+.cht.com.tw': 'https://dns.hinet.net/dns-query'
    '+.hinet.net': 'https://dns.hinet.net/dns-query'
    '+.emome.net': 'https://dns.hinet.net/dns-query'
    '+.tw': 'https://dns.twnic.tw/dns-query'
    '+.taipei': 'https://dns.twnic.tw/dns-query'
    '+.he.net': 'https://ordns.he.net/dns-query'
    'raw.githubusercontent.com': '8.8.8.8'
    '+.meiquankongjian.com': '8.8.8.8'
    '+.getxlx.com': '8.8.8.8'
    '+.nachoneko.shop': '8.8.8.8'
    '+.ptrecord.com': '8.8.8.8'
    '+.bing.cn': '8.8.8.8'
    '+.bing.com': '8.8.8.8'
  {% else %}
    {% if request.dns == "host" %}
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  listen: 1053
  nameserver:
    - 114.114.114.114
    - 223.5.5.5
    - 8.8.8.8
  fallback: []
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 0.0.0.0/8
      - 10.0.0.0/8
      - 100.64.0.0/10
      - 127.0.0.0/8
      - 169.254.0.0/16
      - 172.16.0.0/12
      - 192.0.0.0/24
      - 192.0.2.0/24
      - 192.88.99.0/24
      - 192.168.0.0/16
      - 198.18.0.0/15
      - 198.51.100.0/24
      - 203.0.113.0/24
      - 224.0.0.0/4
      - 240.0.0.0/4
      - 255.255.255.255/32
    domain:
      - "+.google.com"
      - "+.facebook.com"
      - "+.youtube.com"
      - "+.githubusercontent.com"
      - "+.googlevideo.com"
      - "+.msftconnecttest.com"
      - "+.msftncsi.com"
      - msftconnecttest.com
      - msftncsi.com
  fake-ip-filter:
    - '+.*'
  nameserver-policy:
    'talk.google.com': '108.177.125.188'
    'mtalk.google.com': '108.177.125.188'
    'alt1-mtalk.google.com': '3.3.3.3'
    'alt2-mtalk.google.com': '3.3.3.3'
    'alt3-mtalk.google.com': '74.125.200.188'
    'alt4-mtalk.google.com': '74.125.200.188'
    'alt5-mtalk.google.com': '3.3.3.3'
    'alt6-mtalk.google.com': '3.3.3.3'
    'alt7-mtalk.google.com': '74.125.200.188'
    'alt8-mtalk.google.com': '3.3.3.3'
    'blog.google': '119.29.29.29'
    'googletraveladservices.com': '119.29.29.29'
    'dl.google.com': '119.29.29.29'
    'dl.l.google.com': '119.29.29.29'
    'clientservices.googleapis.com': '119.29.29.29'
    'update.googleapis.com': '119.29.29.29'
    'translate.googleapis.com': '119.29.29.29'
    'fonts.googleapis.com': '119.29.29.29'
    'fonts.gstatic.com': '119.29.29.29'
    'networking.apple': 'https://doh.dns.apple.com/dns-query'
    '*.icloud.com': 'https://doh.dns.apple.com/dns-query'
    '*.google': '8.8.8.8'
    '*.google.com': '8.8.8.8'
    '*.google.com.??': '8.8.8.8'
    '*.gstatic.com': '8.8.8.8'
    '*.ggpht.com': '8.8.8.8'
    '*.googleusercontent.com': '8.8.8.8'
    '*.1e100.net': '8.8.8.8'
    '*.youtube': '8.8.8.8'
    '*.youtube.com': '8.8.8.8'
    '*.ytimg.com': '8.8.8.8'
    '*.googlevideo.com': '8.8.8.8'
    '*.gvt?.com': '8.8.8.8'
    '*.recaptcha.net': '8.8.8.8'
    '*.gmail.com': '8.8.8.8'
    '*.googlesource.com': '8.8.8.8'
    '*.googleadservices.com': '8.8.8.8'
    '*.doubleclick.net': '8.8.8.8'
    '*.adsense.com': '8.8.8.8'
    '*.adsensecustomsearchads.com': '8.8.8.8'
    '*.adsenseformobileapps.com': '8.8.8.8'
    '*.gle': '8.8.8.8'
    'goo.gl': '8.8.8.8'
    '*.cloudflare.com': '1.1.1.1'
    '*.cloudflarestream.com': '1.1.1.1'
    '*.cloudflareclient.com': '1.1.1.1'
    '*.cloudflareinsights.com': '1.1.1.1'
    '*.every1dns.net': '1.1.1.1'
    '*.cloudflare-dns.com': '1.1.1.1'
    '*.workers.dev': '1.1.1.1'
    '*.alibaba.cn': '223.5.5.5'
    '*.alibaba.com.cn': '223.5.5.5'
    '*.china.alibaba.com': '223.5.5.5'
    '*.1688.com': '223.5.5.5'
    '*.taobao.com': '223.5.5.5'
    '*.tbcache.com': '223.5.5.5'
    '*.tmall.com': '223.5.5.5'
    '*.alicdn.com': '223.5.5.5'
    '*.aliyundrive.com': '223.5.5.5'
    '*.aliyun.*': '223.5.5.5'
    '*.aliyuncdn.*': '223.5.5.5'
    '*.aliyunddos????.com': '223.5.5.5'
    '*.aliyuncs.com': '223.5.5.5'
    '*.aliyundunwaf.com': '223.5.5.5'
    '*.aliapp.com': '223.5.5.5'
    '*.aliapp.org': '223.5.5.5'
    '*.alibabausercontent.com': '223.5.5.5'
    '*.mmstat.com': '223.5.5.5'
    'tb.cn': '223.5.5.5'
    '*.alipay.com': '223.5.5.5'
    '*.alipay.com.cn': '223.5.5.5'
    '*.alipaydns.com': '223.5.5.5'
    '*.alipayeshop.com': '223.5.5.5'
    '*.alipaylog.com': '223.5.5.5'
    '*.alipayobjects.com': '223.5.5.5'
    '*.alipay-eco.com': '223.5.5.5'
    '*.tencent.com': '119.29.29.29'
    '*.qcloud.com': '119.29.29.29'
    '*.qcloudcdn.cn': '119.29.29.29'
    '*.qcloudcdn.com': '119.29.29.29'
    '*.qcloudcos.com': '119.29.29.29'
    '*.qcloudimg.com': '119.29.29.29'
    '*.qcloudcjgj.com': '119.29.29.29'
    '*.qcloudwzgj.com': '119.29.29.29'
    '*.qcloudzygj.com': '119.29.29.29'
    '*.myqcloud.com': '119.29.29.29'
    '*.tencent-cloud.net': '119.29.29.29'
    '*.tencentcloud-aiot.com': '119.29.29.29'
    '*.tencentcloudapi.com': '119.29.29.29'
    '*.tencentcloudcr.com': '119.29.29.29'
    '*.tencentcloudmarket.com': '119.29.29.29'
    '*.qq.com': '119.29.29.29'
    '*.qlogo.cn': '119.29.29.29'
    '*.qpic.cn': '119.29.29.29'
    '*.weixin.qq.com': '119.29.29.29'
    '*.wx.qq.com': '119.29.29.29'
    '*.weixin.com': '119.29.29.29'
    '*.weixinbridge.com': '119.29.29.29'
    '*.wechat.com': '119.29.29.29'
    '*.servicewechat.com': '119.29.29.29'
    '*.weiyun.com': '119.29.29.29'
    '*.gtimg.cn': '119.29.29.29'
    '*.idqqimg.com': '119.29.29.29'
    '*.cdn-go.cn': '119.29.29.29'
    '*.smtcdns.com': '119.29.29.29'
    '*.smtcdns.net': '119.29.29.29'
    'url.cn': '119.29.29.29'
    '*.baidu': '180.76.76.76'
    '*.baidu.com': '180.76.76.76'
    '*.bdimg.com': '180.76.76.76'
    '*.bdstatic.com': '180.76.76.76'
    '*.baidupcs.*': '180.76.76.76'
    '*.baiduyuncdn.*': '180.76.76.76'
    '*.baiduyundns.*': '180.76.76.76'
    '*.bdydns.*': '180.76.76.76'
    '*.bdycdn.*': '180.76.76.76'
    '*.bdysite.com': '180.76.76.76'
    '*.bdysites.com': '180.76.76.76'
    '*.baidubce.*': '180.76.76.76'
    '*.bcedns.*': '180.76.76.76'
    '*.bcebos.com': '180.76.76.76'
    '*.bcevod.com': '180.76.76.76'
    '*.bceimg.com': '180.76.76.76'
    '*.bcehost.com': '180.76.76.76'
    '*.bcehosts.com': '180.76.76.76'
    'dwz.cn': '180.76.76.76'
    '*.360.cn': 'https://doh.360.cn/dns-query'
    '*.360safe.com': 'https://doh.360.cn/dns-query'
    '*.360kuai.com': 'https://doh.360.cn/dns-query'
    '*.so.com': 'https://doh.360.cn/dns-query'
    '*.360webcache.com': 'https://doh.360.cn/dns-query'
    '*.qihuapi.com': 'https://doh.360.cn/dns-query'
    '*.qhimg.com': 'https://doh.360.cn/dns-query'
    '*.qhimgs.com': 'https://doh.360.cn/dns-query'
    '*.qhimgs?.com': 'https://doh.360.cn/dns-query'
    '*.qhmsg.com': 'https://doh.360.cn/dns-query'
    '*.qhres.com': 'https://doh.360.cn/dns-query'
    '*.qhres?.com': 'https://doh.360.cn/dns-query'
    '*.dhrest.com': 'https://doh.360.cn/dns-query'
    '*.qhupdate.com': 'https://doh.360.cn/dns-query'
    '*.yunpan.cn': 'https://doh.360.cn/dns-query'
    '*.yunpan.com.cn': 'https://doh.360.cn/dns-query'
    '*.yunpan.com': 'https://doh.360.cn/dns-query'
    'urlqh.cn': 'https://doh.360.cn/dns-query'
    'upos-sz-mirrorali.bilivideo.com': '223.5.5.5'
    'upos-sz-mirrorali?.bilivideo.com': '223.5.5.5'
    'upos-sz-mirrorali??.bilivideo.com': '223.5.5.5'
    'upos-sz-mirrorbos.bilivideo.com': '180.76.76.76'
    'upos-sz-mirrorcos.bilivideo.com': '119.29.29.29'
    'upos-sz-mirrorcos?.bilivideo.com': '119.29.29.29'
    'upos-sz-mirrorcos??.bilivideo.com': '119.29.29.29'
    'upos-sz-upcdnbd??.bilivideo.com': '180.76.76.76'
    'upos-sz-upcdntx.bilivideo.com': '119.29.29.29'
    '*.cht.com.tw': 'https://dns.hinet.net/dns-query'
    '*.hinet.net': 'https://dns.hinet.net/dns-query'
    '*.emome.net': 'https://dns.hinet.net/dns-query'
    '*.tw': 'https://dns.twnic.tw/dns-query'
    '*.taipei': 'https://dns.twnic.tw/dns-query'
    '*.he.net': 'https://ordns.he.net/dns-query'
    'raw.githubusercontent.com': '8.8.8.8'
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
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system,119.29.29.29,223.5.5.5
allow-udp-proxy = false
host = 127.0.0.1

[Proxy]

[Remote Proxy]

[Proxy Group]

[Rule]

[Remote Rule]

[URL Rewrite]
enable = true
^https?:\/\/(www.)?(g|google)\.cn https://www.google.com 302

[Remote Rewrite]
https://raw.githubusercontent.com/Loon0x00/LoonExampleConfig/master/Rewrite/AutoRewrite_Example.list,auto

[MITM]
hostname = *.example.com,*.sample.com
enable = true
skip-server-cert-verify = true
#ca-p12 =
#ca-passphrase =

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
network_check_url=http://bing.com/
server_check_url=http://cp.cloudflare.com/generate_204
excluded_routes=192.168.0.0/16, 193.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8
dns_exclusion_list = *.lan, cable.auth.com, *.msftconnecttest.com, *.msftncsi.com, network-test.debian.org, detectportal.firefox.com, resolver1.opendns.com, *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com, stun.*, global.turn.twilio.com, global.stun.twilio.com, localhost.*.qq.com, *.logon.battlenet.com.cn, *.logon.battle.net, *.blzstatic.cn, music.163.com, *.music.163.com, *.126.net, musicapi.taihe.com, music.taihe.com, songsearch.kugou.com, trackercdn.kugou.com, *.kuwo.cn, api-jooxtt.sanook.com, api.joox.com, joox.com, y.qq.com, *.y.qq.com, streamoc.music.tc.qq.com, mobileoc.music.tc.qq.com, isure.stream.qqmusic.qq.com, dl.stream.qqmusic.qq.com, aqqmusic.tc.qq.com, amobile.music.tc.qq.com, *.xiami.com, *.music.migu.cn, music.migu.cn, proxy.golang.org, *.mcdn.bilivideo.cn, *.cmpassport.com, id6.me, open.e.189.cn, mdn.open.wo.cn, opencloud.wostore.cn, auth.wosms.cn, *.jegotrip.com.cn, *.icitymobile.mobi, *.pingan.com.cn, *.cmbchina.com, pool.ntp.org, *.pool.ntp.org, ntp.*.com, time.*.com, ntp?.*.com, time?.*.com, time.*.gov, time.*.edu.cn, *.ntp.org.cn, PDC._msDCS.*.*, DC._msDCS.*.*, GC._msDCS.*.*
geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/IP_API.js
# 指定在某个 Wi-Fi 下暂停 Quantumult X
{% if exists("request.who") %}
  {% if request.who == "self" %}
    running_mode_trigger=filter, filter, Cccccc:all_direct, zxcvawer:all_direct, Cccccc_5G:all_direct
  {% else %}
    {% if request.who == "lulu" %}
      running_mode_trigger=filter, filter, Society-5G:all_direct, Society:all_direct
    {% else %}
      running_mode_trigger=filter, filter, INFINITY-WORLD:all_direct, nana:all_direct
      ;ssid_suspended_list=LINK_22E174, LINK_22E175
    {% endif %}
  {% endif %}
{% endif %}

[dns]
prefer-doh3
# > Modify Contents
# Firebase Cloud Messaging
address = /talk.google.com/108.177.125.188
address = /mtalk.google.com/108.177.125.188
address = /alt1-mtalk.google.com/3.3.3.3
address = /alt2-mtalk.google.com/3.3.3.3
address = /alt3-mtalk.google.com/74.125.200.188
address = /alt4-mtalk.google.com/74.125.200.188
address = /alt5-mtalk.google.com/3.3.3.3
address = /alt6-mtalk.google.com/3.3.3.3
address = /alt7-mtalk.google.com/74.125.200.188
address = /alt8-mtalk.google.com/3.3.3.3
# Google CDN
doh-server = /blog.google/https://doh.pub/dns-query
doh-server = /googletraveladservices.com/https://doh.pub/dns-query
doh-server = /dl.google.com/https://doh.pub/dns-query
doh-server = /dl.l.google.com/https://doh.pub/dns-query
doh-server = /clientservices.googleapis.com/https://doh.pub/dns-query
doh-server = /update.googleapis.com/https://doh.pub/dns-query
doh-server = /translate.googleapis.com/https://doh.pub/dns-query
doh-server = /fonts.googleapis.com/https://doh.pub/dns-query
doh-server = /fonts.gstatic.com/https://doh.pub/dns-query

# > Router Admin Panel
# Ubiquiti Unifi Network App
server = /*.id.ui.direct/system
# Ubiquiti Unifi Portal
# server = /unifi.ui.com/system
# Ubiquiti Unifi OS
server = /unifi.local/system
# Ubiquiti Unifi Controller
# server = /network.unifi.ui.com/system
# Ubiquiti Amplifi Router
server = /amplifi.lan/system
# Synology Router
server = /router.synology.com/system
# Razer Sila Router
server = /sila.razer.com/system
# Asus Router
server = /router.asus.com/system
# Netgear Router
server = /routerlogin.net/system
# Netgear Obri Router
server = /orbilogin.com/system
# Linksys Router
server = /www.LinksysSmartWiFi.com/system
server = /LinksysSmartWiFi.com/system
server = /myrouter.local/system
# Aurba Router
server = /instant.arubanetworks.com/system
server = /setmeup.arubanetworks.com/system
# 小米 Mi WiFi Router
server = /www.miwifi.com/system
server = /miwifi.com/system
# 华为 Huawei Router
server = /mediarouter.home/system
# TP-Link Router
server = /tplogin.cn/system
server = /tplinklogin.net/system
server = /tplinkwifi.net/system
# 水星 MERCURY Router
server = /melogin.cn/system
# 迅捷 FAST Router
server = /falogin.cn/system
# 腾达 Tenda Router
server = /tendawifi.com/system
# 磊科 Netcore Router
server = /leike.cc/system
# 中兴 ZTE Router
server = /zte.home/system
# 斐讯 PHICOMM Router
server = /p.to/system
server = /phicomm.me/system
# 极路由 HiWiFi Router
server = /hiwifi.com/system
# 迅雷路由
server = /peiluyou.com/system

# > Apple
doh-server = /networking.apple/https://doh.dns.apple.com/dns-query
# Apple.com
# doh-server = /*.apple.com/https://doh.dns.apple.com/dns-query
# iCloud.com
doh-server = /*.icloud.com/https://doh.dns.apple.com/dns-query

# > Alphabet
doh-server = /*.google/https://dns.google/dns-query
doh-server = /*.google.com/https://dns.google/dns-query
doh-server = /*.google.com.??/https://dns.google/dns-query
# Google sites
# doh-server = /*.goog/https://dns.google/dns-query
# Google 静态资源
doh-server = /*.gstatic.com/https://dns.google/dns-query
# Google Photos
doh-server = /*.ggpht.com/https://dns.google/dns-query
# Google 用户上传数据
doh-server = /*.googleusercontent.com/https://dns.google/dns-query
# Google APIs
# doh-server = /*.googleapis.com/https://dns.google/dns-query
# Google backbone
doh-server = /*.1e100.net/https://dns.google/dns-query
# Youtube sites
doh-server = /*.youtube/https://dns.google/dns-query
# Youtube
doh-server = /*.youtube.com/https://dns.google/dns-query
# Youtube 图片
doh-server = /*.ytimg.com/https://dns.google/dns-query
# Youtube Video
doh-server = /*.googlevideo.com/https://dns.google/dns-query
# Google Video Thumbnails
doh-server = /*.gvt?.com/https://dns.google/dns-query
# reCaptcha
doh-server = /*.recaptcha.net/https://dns.google/dns-query
# Gmail
doh-server = /*.gmail.com/https://dns.google/dns-query
# Google Source
doh-server = /*.googlesource.com/https://dns.google/dns-query
# Google AD Services
doh-server = /*.googleadservices.com/https://dns.google/dns-query
# DoubleClick
doh-server = /*.doubleclick.net/https://dns.google/dns-query
# AdSense
doh-server = /*.adsense.com/https://dns.google/dns-query
# AdSense Custom Search Ads
doh-server = /*.adsensecustomsearchads.com/https://dns.google/dns-query
# AdSense for mobile apps
doh-server = /*.adsenseformobileapps.com/https://dns.google/dns-query
# Google shortened URLs
doh-server = /*.gle/https://dns.google/dns-query
# Google URL Shortener
doh-server = /goo.gl/https://dns.google/dns-query

# > Cloudflare
doh-server = /*.cloudflare.com/https://cloudflare-dns.com/dns-query
# Cloudflare Stream
doh-server = /*.cloudflarestream.com/https://cloudflare-dns.com/dns-query
# Cloudflare Client
doh-server = /*.cloudflareclient.com/https://cloudflare-dns.com/dns-query
# Cloudflare Web Analytics
doh-server = /*.cloudflareinsights.com/https://cloudflare-dns.com/dns-query
# Cloudflare 1.1.1.1
doh-server = /*.every1dns.net/https://cloudflare-dns.com/dns-query
# Cloudflare SSL Certificate
# doh-server = /*.cloudflaressl.com/https://cloudflare-dns.com/dns-query
# Cloudflare DNS
doh-server = /*.cloudflare-dns.com/https://cloudflare-dns.com/dns-query
# CloudFlare Workers
doh-server = /*.workers.dev/https://cloudflare-dns.com/dns-query

# > 阿里巴巴
doh-server = /*.alibaba.cn/https://dns.alidns.com/dns-query
doh-server = /*.alibaba.com.cn/https://dns.alidns.com/dns-query
# Alibaba 中国
doh-server = /*.china.alibaba.com/https://dns.alidns.com/dns-query
# 1688
doh-server = /*.1688.com/https://dns.alidns.com/dns-query
# 淘宝
doh-server = /*.taobao.com/https://dns.alidns.com/dns-query
# 淘宝 缓存
doh-server = /*.tbcache.com/https://dns.alidns.com/dns-query
# 天猫
doh-server = /*.tmall.com/https://dns.alidns.com/dns-query
# 阿里 CDN
doh-server = /*.alicdn.com/https://dns.alidns.com/dns-query
# 阿里云盘
doh-server = /*.aliyundrive.com/https://dns.alidns.com/dns-query
# 阿里云
doh-server = /*.aliyun.*/https://dns.alidns.com/dns-query
# 阿里云 CDN
doh-server = /*.aliyuncdn.*/https://dns.alidns.com/dns-query
# 阿里云 DDoS防护
doh-server = /*.aliyunddos????.com/https://dns.alidns.com/dns-query
# 阿里云API服务
doh-server = /*.aliyuncs.com/https://dns.alidns.com/dns-query
# 阿里云Web应用防火墙
doh-server = /*.aliyundunwaf.com/https://dns.alidns.com/dns-query
# 云引擎应用平台
doh-server = /*.aliapp.com/https://dns.alidns.com/dns-query
# 上云平台
doh-server = /*.aliapp.org/https://dns.alidns.com/dns-query
# 阿里用户上传资料
doh-server = /*.alibabausercontent.com/https://dns.alidns.com/dns-query
# mmstat 数据统计 广告追踪
doh-server = /*.mmstat.com/https://dns.alidns.com/dns-query
# 淘宝短网址
doh-server = /tb.cn/https://dns.alidns.com/dns-query

# > 蚂蚁集团
doh-server = /*.alipay.com/https://dns.alidns.com/dns-query
doh-server = /*.alipay.com.cn/https://dns.alidns.com/dns-query
# 支付宝 HTTP DNS
doh-server = /*.alipaydns.com/https://dns.alidns.com/dns-query
# 支付宝 商家资源
doh-server = /*.alipayeshop.com/https://dns.alidns.com/dns-query
# 支付宝 Mdap
doh-server = /*.alipaylog.com/https://dns.alidns.com/dns-query
# 支付宝 静态资源
doh-server = /*.alipayobjects.com/https://dns.alidns.com/dns-query
# 支付宝 开放技术生态体系
doh-server = /*.alipay-eco.com/https://dns.alidns.com/dns-query

# > 腾讯
doh-server = /*.tencent.com/https://doh.pub/dns-query
# 腾讯云
doh-server = /*.qcloud.com/https://doh.pub/dns-query
# 腾讯云CDN
doh-server = /*.qcloudcdn.cn/https://doh.pub/dns-query
doh-server = /*.qcloudcdn.com/https://doh.pub/dns-query
# 腾讯云对象储存
doh-server = /*.qcloudcos.com/https://doh.pub/dns-query
# 腾讯云静态资源
doh-server = /*.qcloudimg.com/https://doh.pub/dns-query
# 腾讯云超级管家
doh-server = /*.qcloudcjgj.com/https://doh.pub/dns-query
# 腾讯云网站管家
doh-server = /*.qcloudwzgj.com/https://doh.pub/dns-query
# 腾讯云主页管家
doh-server = /*.qcloudzygj.com/https://doh.pub/dns-query
# 腾讯开放云
doh-server = /*.myqcloud.com/https://doh.pub/dns-query
# 腾讯云
doh-server = /*.tencent-cloud.net/https://doh.pub/dns-query
# 腾讯云aiot解决方案
doh-server = /*.tencentcloud-aiot.com/https://doh.pub/dns-query
# 腾讯云API
doh-server = /*.tencentcloudapi.com/https://doh.pub/dns-query
# 腾讯云容器镜像服务TCR
doh-server = /*.tencentcloudcr.com/https://doh.pub/dns-query
# 腾讯云云市场
doh-server = /*.tencentcloudmarket.com/https://doh.pub/dns-query
# QQ
doh-server = /*.qq.com/https://doh.pub/dns-query
# 腾讯头像
doh-server = /*.qlogo.cn/https://doh.pub/dns-query
# 腾讯图片
doh-server = /*.qpic.cn/https://doh.pub/dns-query
# 微信
doh-server = /*.weixin.qq.com/https://doh.pub/dns-query
doh-server = /*.wx.qq.com/https://doh.pub/dns-query
doh-server = /*.weixin.com/https://doh.pub/dns-query
# 微信公众平台
doh-server = /*.weixinbridge.com/https://doh.pub/dns-query
# WeChat
doh-server = /*.wechat.com/https://doh.pub/dns-query
# 微信小程序
doh-server = /*.servicewechat.com/https://doh.pub/dns-query
# 微云
doh-server = /*.weiyun.com/https://doh.pub/dns-query
# 腾讯 图片 静态资源
doh-server = /*.gtimg.cn/https://doh.pub/dns-query
doh-server = /*.idqqimg.com/https://doh.pub/dns-query
# 腾讯 静态资源 CDN
doh-server = /*.cdn-go.cn/https://doh.pub/dns-query
# 腾讯云 智能云解析DNS
doh-server = /*.smtcdns.com/https://doh.pub/dns-query
doh-server = /*.smtcdns.net/https://doh.pub/dns-query
# 腾讯短网址
doh-server = /url.cn/https://doh.pub/dns-query

# > 百度
server = /*.baidu/180.76.76.76
server = /*.baidu.com/180.76.76.76
# 百度 静态资源
server = /*.bdimg.com/180.76.76.76
server = /*.bdstatic.com/180.76.76.76
# 百度网盘
server = /*.baidupcs.*/180.76.76.76
# 百度云CDN
server = /*.baiduyuncdn.*/180.76.76.76
# 百度云DNS
server = /*.baiduyundns.*/180.76.76.76
# 百度云 DNS
server = /*.bdydns.*/180.76.76.76
# 百度云 CDN
server = /*.bdycdn.*/180.76.76.76
# 百度云 域名
server = /*.bdysite.com/180.76.76.76
server = /*.bdysites.com/180.76.76.76
# 百度智能云
server = /*.baidubce.*/180.76.76.76
# 百度智能云 DNS
server = /*.bcedns.*/180.76.76.76
# 百度智能云 对象存储BOS
server = /*.bcebos.com/180.76.76.76
# 百度智能云 播放器服务
server = /*.bcevod.com/180.76.76.76
# 百度智能云 图片服务
server = /*.bceimg.com/180.76.76.76
# 百度智能云 主机
server = /*.bcehost.com/180.76.76.76
server = /*.bcehosts.com/180.76.76.76
# 百度短网址
server = /dwz.cn/180.76.76.76

# > 360
# 360安全中心
doh-server = /*.360.cn/https://doh.360.cn/dns-query
# 360安全卫士
doh-server = /*.360safe.com/https://doh.360.cn/dns-query
# 360快资讯
doh-server = /*.360kuai.com/https://doh.360.cn/dns-query
# 360搜索
doh-server = /*.so.com/https://doh.360.cn/dns-query
# 360网页快照服务
doh-server = /*.360webcache.com/https://doh.360.cn/dns-query
# 奇虎api
doh-server = /*.qihuapi.com/https://doh.360.cn/dns-query
# 360图床
doh-server = /*.qhimg.com/https://doh.360.cn/dns-query
doh-server = /*.qhimgs.com/https://doh.360.cn/dns-query
doh-server = /*.qhimgs?.com/https://doh.360.cn/dns-query
# 360
doh-server = /*.qhmsg.com/https://doh.360.cn/dns-query
# 奇虎静态资源
doh-server = /*.qhres.com/https://doh.360.cn/dns-query
doh-server = /*.qhres?.com/https://doh.360.cn/dns-query
# 导航静态文件
doh-server = /*.dhrest.com/https://doh.360.cn/dns-query
# 360
doh-server = /*.qhupdate.com/https://doh.360.cn/dns-query
# 360安全云盘
doh-server = /*.yunpan.cn/https://doh.360.cn/dns-query
doh-server = /*.yunpan.com.cn/https://doh.360.cn/dns-query
doh-server = /*.yunpan.com/https://doh.360.cn/dns-query
# 360短网址
doh-server = /urlqh.cn/https://doh.360.cn/dns-query

# > BiliBili
server = /*.bilibili.com/system
# BiliBili API
server = /*.biliapi.com/system
server = /*.biliapi.net/system
# BiliBili CDN
server = /*.bilicdn?.com/system
# BiliBili 静态资源
server = /*.hdslb.com/system
server = /*.hdslb.net/system
# BiliBili 视频
server = /cn-hk-eq-bcache-??.bilivideo.com/system
# BiliBili upos视频服务器（akamai）
server = /upos-hz-mirrorakam.akamaized.net/system
# BiliBili upos视频服务器（asia-abroad.com）
server = /upos-sz-mirrorasiaov.bilibilivideo.com/system
# BiliBili upos视频服务器（阿里云）
doh-server = /upos-sz-mirrorali.bilivideo.com/https://dns.alidns.com/dns-query
doh-server = /upos-sz-mirrorali?.bilivideo.com/https://dns.alidns.com/dns-query
doh-server = /upos-sz-mirrorali??.bilivideo.com/https://dns.alidns.com/dns-query
# BiliBili upos视频服务器（百度云）
server = /upos-sz-mirrorbos.bilivideo.com/180.76.76.76
# BiliBili upos视频服务器（腾讯云）
doh-server = /upos-sz-mirrorcos.bilivideo.com/https://doh.pub/dns-query
doh-server = /upos-sz-mirrorcos?.bilivideo.com/https://doh.pub/dns-query
doh-server = /upos-sz-mirrorcos??.bilivideo.com/https://doh.pub/dns-query
# BiliBili upos视频服务器（华为云）
server = /upos-sz-mirrorhw.bilivideo.com/system
server = /upos-sz-mirrorhw?.bilivideo.com/system
# BiliBili upos视频服务器（金山云）
server = /upos-sz-mirrorks3.bilivideo.com/system
server = /upos-sz-mirrorks3?.bilivideo.com/system
# BiliBili upos视频服务器（七牛云）
server = /upos-sz-mirrorkodo.bilivideo.com/system
server = /upos-sz-mirrorkodo?.bilivideo.com/system
# BiliBili upos视频服务器（网宿）
server = /upos-sz-mirrorwcs.bilivideo.com/system
server = /upos-sz-mirrorwcs?.bilivideo.com/system
# BiliBili upos视频服务器（迅雷）
server = /upos-sz-mirrorxycdn.bilivideo.com/system
# BiliBili upos视频服务器（百度云）
server = /upos-sz-upcdnbd??.bilivideo.com/180.76.76.76
# BiliBili upos视频服务器
server = /upos-sz-upcdnhw.bilivideo.com/system
# BiliBili upos视频服务器（腾讯云）
doh-server = /upos-sz-upcdntx.bilivideo.com/https://doh.pub/dns-query
# BiliBili upos视频服务器
server = /upos-sz-upcdnws.bilivideo.com/system
server = /upos-tf-all-js.bilivideo.com/system
# BiliBili mCDN视频服务器
server = /*.mcdn.bilivideo.com/system
# BiliBili 视频
server = /*.bilivideo.com/system
server = /*.bilivideo.cn/system
# BiliBili短网址
server = /acg.tv/system

# > 京东
server = /*.jd.com/system
# 京东 静态资源
server = /*.360buyimg.com/system
# 京东云
server = /*.jdcloud.com/system
# 京东云 缓存和存储
server = /*.jcloudstatic.com/system
# 京东云 静态资源
server = /*.jcloudstatic.net/system
# 京东云 全局负载均衡
server = /*.jdgslb.com/system
# 京东短网址
server = /3.cn/system

# > iQDNS
doh-server = /*.iqdns.xyz/https://a.passcloud.xyz/dns-query
doh-server = /*.iqdnsio.co/https://a.passcloud.xyz/dns-query
doh-server = /*.iqiq.io/https://a.passcloud.xyz/dns-query
doh-server = /*.passcloud.xyz/https://a.passcloud.xyz/dns-query
# iQZone
doh-server = /uuu.glass/https://a.passcloud.xyz/dns-query
doh-server = /*.uuu.glass/https://a.passcloud.xyz/dns-query
doh-server = /*.uuuglass.co/https://a.passcloud.xyz/dns-query
doh-server = /*.leoddns.cn/https://a.passcloud.xyz/dns-query
doh-server = /*.gov-ddns.cn/https://a.passcloud.xyz/dns-query
doh-server = /*.daliddns.cn/https://a.passcloud.xyz/dns-query
doh-server = /*.xn--mes98khzje07c.xyz/https://a.passcloud.xyz/dns-query
doh-server = /*.9218561.xyz/https://a.passcloud.xyz/dns-query
doh-server = /*.211129.xyz/https://a.passcloud.xyz/dns-query
doh-server = /*.gia.wiki/https://a.passcloud.xyz/dns-query
doh-server = /*.checkmails.xyz/https://a.passcloud.xyz/dns-query
doh-server = /*.iqyun.zone/https://a.passcloud.xyz/dns-query
doh-server = /*.ddns-pop.cyou/https://a.passcloud.xyz/dns-query

# > 🇨🇳 CN
# CNNIC SDNS
# 中国政府网
# server = /*.gov.cn/1.2.4.8
# server = /*.政务/1.2.4.8

# > 🇭🇰 HK
# PCCW Enterprises Limited
# server = /*.pccw.com/dns1.pccw.com
# 1O1O
# server = /*.1010.com.hk/dns1.pccw.com
# csl.
# server = /*.hkcsl.com/dns1.pccw.com
# The CLUB by HKT
# server = /*.theclub.com.hk/dns1.pccw.com
# now.com
# server = /*.now.com/dns2.pccw.com
# Now E
# server = /*.nowe.com/dns2.pccw.com
# Now TV
# server = /*.now-tv.com/dns2.pccw.com
# MOOV
# server = /*.moov.hk/dns3.pccw.com
# viu
# server = /*.viu.com/dns3.pccw.com
# viu tv
# server = /*.viu.tv/dns3.pccw.com
# Hong Kong Cable Television Limited
# server = /*.hkcable.com.hk/dns1.hkcable.com.hk
# i-CABLE
# server = /*.i-cable.com/dns2.hkcable.com.hk
# CABLE TV Service
# server = /*.cabletv.com.hk/dns2.hkcable.com.hk
# KDDI Hong Kong Limited
# server = /*.hk.kddi.com/apple.kdd.net.hk

# > 🇹🇼 TW
# 中华电信
doh-server = /*.cht.com.tw/https://dns.hinet.net/dns-query
# 中华电信HiNet
doh-server = /*.hinet.net/https://dns.hinet.net/dns-query
# 中华电信emome
doh-server = /*.emome.net/https://dns.hinet.net/dns-query
# So-net Entertainment Taiwan
# server = /*.so-net.net.tw/ns1.so-net.net.tw
# server = /*.so-net.tw/ns1.so-net.net.tw
# Taiwan Network Information Center
doh-server = /*.tw/https://dns.twnic.tw/dns-query
doh-server = /*.taipei/https://dns.twnic.tw/dns-query

# > 🇺🇸 US
# Hurricane Electric
doh-server = /*.he.net/https://ordns.he.net/dns-query

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
static=Hax, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=Other Games, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Game.png
static=B1gProxy, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Global.png
static=Trading, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Global.png
static=Telegram, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Telegram.png
static=Netflix, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Netflix.png
static=GlobalMedia, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Streaming.png
static=GlobalGameDownload, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=PrivateTracker, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Download.png
static=SougouInput, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
static=Hijacking, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Alpha/Advertising.png
static=HK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=AutoHK 🇭🇰, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Hong_Kong.png
static=TW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=AutoTW 🇨🇳, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/CN.png
static=KR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=AutoKR 🇰🇷, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/KR.png
static=JP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=AutoJP 🇯🇵, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Japan.png
static=SGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
static=AutoSGP 🇸🇬, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Singapore.png
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

[server_remote]

[filter_remote]

[rewrite_remote]
https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf, tag = boxjs, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/TikTok.conf, tag = TikTok, update-interval=172800, opt-parser=false, enabled=true
# VIP解锁
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/Unlock.qxrewrite, tag=UnlockVIP, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/qiangxinglin/Emby/main/QuantumultX/emby.conf, tag=EmbyVIP, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/I-am-R-E/QuantumultX/main/MeiYanXiangJi.conf, tag=MyxjVIP, update-interval=86400, opt-parser=false, enabled=true
#功能增强
https://raw.githubusercontent.com/Orz-3/QuantumultX/master/JD_TB_price.conf, tag=比价脚本, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/Orz-3/QuantumultX/master/Netflix_ratings.conf, tag=Netflix评分, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zZPiglet/Task/master/zhihu.conf, tag=知乎不跳转, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zZPiglet/Task/master/UnblockURLinWeChat.conf, tag=微信助手, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/DualSubs/DualSubs/main/qxrewrite/DualSubs.qxrewrite, tag=DualSubs, update-interval=86400, opt-parser=false, enabled=false
https://raw.githubusercontent.com/DualSubs/DualSubs/main/qxrewrite/DualSubs.YouTube.qxrewrite, tag=DualSubsYouTube, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/VirgilClyne/iRingo/main/qxrewrite/Siri.qxrewrite, tag=iRingoSiri, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/VirgilClyne/iRingo/main/qxrewrite/Location.qxrewrite, tag=iRingoLocation, update-interval=86400, opt-parser=false, enabled=true
#去广告
https://raw.githubusercontent.com/app2smile/rules/master/module/bilibili-qx.conf, tag=批站去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/tieba-qx.conf, tag=贴吧去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/qidian.conf, tag=起点去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/YoutubeAds.conf, tag=油管去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/vgtime.conf, tag=vgTime去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/zhihu.conf, tag=知乎去广告, update-interval=86400, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Applet.conf, tag=微信小程序去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/zmqcherish/proxy-script/main/weibo.conf, tag=微博国内版去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Weibo.conf, tag=微博国际版去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Amap.conf, tag=高德地图去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Ximalaya.conf, tag=喜马拉雅去广告, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/app2smile/rules/master/module/adsense.conf, tag=去广告联盟, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rewrite/QuantumultX/AllInOne/AllInOne.conf, tag = A1去广告, update-interval=86400, opt-parser=false, enabled=false
#Cookie
https://raw.githubusercontent.com/Fvr9W/sub/master/rules/GetCookie.conf, tag = GetCookie, update-interval=86400, opt-parser=false, enabled = false

[server_local]

[task_local]
# 10000  (By @chavyleung)
# 打开 APP 手动签到一次: 访问下右下角 `我` > `签到` (头像下面)
1 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10000/10000.js, tag=10000, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/10000.png,enabled=true

# 10010  (By @chavyleung)
# 打开 APP , 进入签到页面, 系统提示: 获取刷新链接: 成功
# 然后手动签到 1 次, 系统提示: 获取Cookie: 成功 (每日签到)
# 首页>天天抽奖, 系统提示 2 次: 获取Cookie: 成功 (登录抽奖) 和 获取Cookie: 成功 (抽奖次数)
1 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/10010/10010.js, tag=10010, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/10010.png,enabled=true

# bilibili  (By @chavyleung)
# 打开浏览器访问: https://www.bilibili.com 或 https://live.bilibili.com
2 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/bilibili/bilibili.js, tag=bilibili, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/bilibili.png,enabled=true

# 百度贴吧  (By @chavyleung)
# 浏览器访问一下: https://tieba.baidu.com 或者 https://tieba.baidu.com/index/
10 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/tieba/tieba.js, tag=百度贴吧, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/tieba.png, enabled=true

# 饿了么   (By @blackmatrix7)
# 打开 APP, 访问下右下角 我的 - 赚吃货豆。
05 10 * * * https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/eleme/eleme_daily.js, tag=ele_领取吃货豆, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/elem.png, enabled=true

# 什么值得买   (By @blackmatrix7)
# 浏览器访问并登录: https://zhiyou.smzdm.com/user/login
5 0 * * * https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/script/smzdm/smzdm_daily.js, tag=sm签到, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/smzdm.png, enabled=true

# 多看阅读  (By @chavyleung)
# `我的` > `签到任务` 等到提示获取 Cookie 成功即可
13 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/duokan/duokan.js, tag=多看, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/duokan.png,enabled=true

# 飞客茶馆  (By @chavyleung)
# 打开 APP, 访问下`个人中心`
3 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/flyertea/flyertea.js, tag=飞客茶馆, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/flyertea.png,enabled=true

# 美团  (By @chavyleung)
# 打开 APP , 然后手动签到 1 次, 系统提示: 获取Cookie: 成功 (首页 > 红包签到)
1 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/meituan/meituan.js, tag=美团, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/meituan.png, enabled=true

# 京东到家  (By @chavyleung)
#打开 APP 手动签到一次: `首页` > `签到` 或者 手机浏览器打开`https://daojia.jd.com/html/index.html` 点击签到
11 0 * * * https://raw.githubusercontent.com/chavyleung/scripts/master/jddj/jddj.js, tag=京东到家, img-url=https://raw.githubusercontent.com/Orz-3/mini/master/Color/jddj.png, enabled=true

[http_backend]

[filter_local]
geoip, cn, direct
final, Final

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
p12 = MIIK6QIBAzCCCrMGCSqGSIb3DQEHAaCCCqQEggqgMIIKnDCCBOcGCSqGSIb3DQEHBqCCBNgwggTUAgEAMIIEzQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIbEPVozocK6kCAggAgIIEoOA7pjAyN8FBSkXmEKV7Zp+NXPy06ERlSF7zZhPOxetwISPDXpF9P51+4ngK7MJRPHYWD4MLEWhaeILQysaOZ3q9OPV7/wMSaNWwUSOCogJijiGGY+H0RECRNT04Zwwki6adi3Wr6NS30ASgBhAyqULjwo8rVt3iqi/ZwjYZsFgl5Qr3s1RzhmZVrNS0UYaHP7Aow5JHm2yJmmrsEC0EyDYFQfo5njHmT2u+95Dkos8XEJFh+vBcyFFqm7Bf6tadrt5eA55ZEBGoEL9mOcLH4G0xr1W049MeBMksEZbdEw5iHfEkgMfuX5Dz6Jd/NynpTEjTqH/O+aL68Nbn1atARxNa/K24yzvgenEsRBgkBNYY7Y+tQHr67wHgiqTZFAV7K545rk2dxBDw0+l2ro4Am3uLq/6QWKgXR3EpQDXSAAy6TLfZ0w3sblg3rZg3uj6tD+VtgLZvGD7t/vHPrrQGCWQVk4/4QXycUejG1eYeEYrFv7TSXaiwWcXp6U2et2PQYRkR1NHy1s5AEnJ39/XLcxTvtydSqjDmoQvklO6BD399pTK3qH6enInaL3+3ac3fCFGRi+YG0aIpm26AxmLoZ0B6DAhhXUh/Cw4o4Mrgq7be4uoNfJEhKHuzRyvz0/Nx4AIAKgq5Vt4dlToGlIzxbwvIp01wDY1clwAo38Wef5nlPJRHDgw5piJ3xX4Q+yKwQWRNqfjh2zLvKLLQgNObc8r63Dqyr02Ap5EJ+KOWWc8u0cFHahgwIvX88u4kNj4tAwJbgUsVUdCXtNfxM2/saeddifaUwz8kNuIglVKx7z5iwPtXrR/CAowY1Y6H9KteOXHvKVxCHASe3Ka9jxvzogmM5pIVOCqHbs5hQCtEs1q1byXXqkTvCgFoZ6CFPTK/xBCntWzrBTiT1FYIIcwdAgEHnXG9JHHpSuQFCR1l3O5jiitGJdcZ8r82BZ5wdTz2IpydMqqhPQDtkFz5HGU/8/+x6ogzjKjuGtct4gBWDFEP0v6LBEP3pmj6sX90w5SDh8SQlPw86trAzo1pciMfKuNdPhpQwb8u438R8y05imSMUOBOYaRxO/A8SFjmnuKtZwZGFcv1z6xHZHwjkLI6hxqu253huJpX0d1jAhCo1wv8V3hDbkc+piXM/Fbc3XE8ecbPVoaEUrUgJRZQy1Yg1OukmV51zNAfwbUiJa1X2SDl47KPeGeKoJDA24XhTyzC6Lb75ZddQ0UyQlNtkwsTtp19hgLv7/CmHs59/rB/vFrYeapWRMiQCrrcbLTgDu/OokdAZouMHaWiom/Yg6o2fZLkdeWYFliFcTlqbGko8b+J12ZXtxV1uEwB1e/rgvxxQQXv0A6jDUEaOa13i+5sGTvmT6iYmm0vy5M/QMr5rauMNdO/9KFwsIs7RIsVsjRxt0NNS635yVIn0uyNa1Vh0UWcac6xcfnB7ct72+ZWHcPv98bK8AE2Je1uoKsl+AKwgSjpqAREtgOmvcqxuQ3qX/9yY6GZbwR3W+NliD5yv1XDuUUnMC67IdGs1fNUK7v81iyhnBl4N3qTG+mKTVW+9ht7Obcy9IsTHkQZ8zQ97npTMIIFrQYJKoZIhvcNAQcBoIIFngSCBZowggWWMIIFkgYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECKv3sJAwUwJOAgIIAASCBMgahXcDpZAX9RBgbcU80N/Nci26UMZZpLP6kcr+uzwGDLIEmoJ7fFO1AJMC7xL/6ZfiuytYjtLSBGXLO55IOYkR7HgzDljdsvFPx0GRA/FOZy1n0mLknT3Vy9I/VUYQTdkAtQVS59hhax/ivZtpdklQuCNSHcUVwqiBiUnwZY2OoIL80glMN2J+FJXzkpT56LBqKq6J2B2u/XmMg5q23x/gqxOi4toN5ZWFDWTrnb1riP9TGy+EeDylr2B0jORCQTBSFSqG2BvNkT/ZkdagwiLO1SCNQ/KfgjC6Pl1olDp3p8MX5wxyyVF1n34B6ClE8g1TwYQA2vsYD7GkN+bbUATie12jNJMe5kKhRZ9mMFE4nJctB3ULeDW0oQ443XUGvqmMyWtpC9VunGRWvOg8JaNJDDho7GuniBIsQpTvlfmg2OjLySKmkly/7e79FIj4ERj4YLcvutmT/UDnctTDlRGBG0OmAQFnKw73o2INSzk8lohQwxSVpyBm7h4ScTFqCuTFNzJGUht03VSl40dyXRX17aKZD3RHtlDmHpJ15jwB2N6wjAJZ9mmbJg2QA/rykCqtZE/vfHtrbXMyZiu167iAyI+4dQJ8i+KpVt9mioWYYFTCz7voe/iNC3mbfPMAxgm6X6bLONJ3goJG0SPuDvoj90b68Zc1jD3vuD6Ee+a16LLq7ZQzt61uuQNaSXz2xOKPAStNn8zFFmoDR/zHkNPnLjntYfoGKP9WgGVZhz4rqQbw3QAvsZmvVcJtNSIaCPLsfBZmR5U5PukTDoqbqc2VZx7LQQobiKcBu7dPX5a8nCt05HqHYJCj1X75Rx6wMhYe1yJlgkChe/t7kmfCwJ9ZyPm2YalV9CMKBueWIu6Ou10pEDHV/lVuW5cFhp8Lk/Q/JF62AMZLs/W6zn5MqxVI6jgW7HyYtny/4gaDfA0nARb7Rc3Rg5/TtEGDMSAXQ00YNUx4ViJWyV6CIdPkNZQgTnm/RdDx/eo4ATYQcrcag+KCrTj/8p5YR5I+ueOJ1lmhTLE6zN5+abgK1agDo5yBb2p8MAMUJNnqENMkj70I1/rVTxT3jnZMqhEMlTjxkDnpzzxDgtuAX4XIdbvhM9M48dCCTSyhlM6TJAzDt47NpoKXAKKR2wEbs7CnZwiev3g+NxPSyDWWUozrfwCMc63X0lumy4Q/UHECQrt56KN6r1pUCLQ6jpsv50V4m76oq50q18Sxu2b7bnF41Dqsy4IFQs54EuW0W6qmuM3xpe3Rdy/41YzpaLs4+xpJloMhYcgMKbgKnAiJPi3j0sZcuExXPDUdMKM/36YVLyHftwdUBgtpNBu/1kg8NKV387OmfKPn4QqcEc9nzo61gXAYm96/IN0/5oLh/ZvlvVBJDTqVirSzMOQZB+aNT2Glt3poJmU8BqXc10l2lW7bHC4xAa/VIQ7KUuTnNIvTla3CmZcf7HYdECj+4iWDCQGgonwU8o9dPc1dre+r9T6Ac35cY+4nHTOXQ4IzbEBvsxAl9HNv2SCLGYPlaDXljUKKkG7njRF7aPFcLCAbPoYaHvS5dg7q9N9kBMX5UC+4tWAIF67I/bflvzyt02/3MldVKXUqFaELkPLMKB+4irCYFuX7251gsg4K4ohe370xgZAwIwYJKoZIhvcNAQkVMRYEFLmN1md+zErF071wjVgouWvMM/s7MGkGCSqGSIb3DQEJFDFcHloAUQB1AGEAbgB0AHUAbQB1AGwAdAAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgADEAOAA1ADIARgA5ADcAQgAgACgAMQAzACAATQBhAHIAIAAyADAAMgAwACkwLTAhMAkGBSsOAwIaBQAEFPIopy1ckNGXJyTwm406SNxD7YpJBAhAmjtNdPbopw==
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
p12 = MIIJKQIBAzCCCO8GCSqGSIb3DQEHAaCCCOAEggjcMIII2DCCA48GCSqGSIb3DQEHBqCCA4AwggN8AgEAMIIDdQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI3fJWfZaNaxgCAggAgIIDSCr2zGhO28dMTINwrCLFUrAePu+yc98x5cpqeACRV6fgBYfamVTP705koLsh0Ex98azK5w5yTm5kVeW2kBsTN23j6sYYy8mvYzsECYzjPy6EUnTjcvAazejxofO/p5mB/ErHDGNXhS++2Q/bvMHTIDpmuvCPnjVePpiBz3E8kAV0CqW+XNWMjMVyITWEJF729LC9IxttznCISZzENzoYHMLBXJExEOnia68Mv4PezOah+Op1ZcJfXZb/f5gSmdCJKmVTDl2fKS7BCPltDgttgBFCHRbgEP2DVsWHuZnnvDoW0GgR+WAdFQnv+Rf6tZ2Y4TIg4T/ko+yLLSbUludm6Ymueb06OXWrM7bqmBR5RqrQRQkIbzDJZ7mnyzYJySp7Jt9IhTmavl3O+vH7bfWD0VmNVOI54yVFETfGq+L+crDdL2MosKMxlKnQa2DrOHVFahwocQd0S5y5I25hieODjoogGOndS08tax7BDNC6YE/H/rQ+F3Eb9kK8ec1mj/HSwvKSX6/360ftR9/f96mAQ+SFi+TF7Y6S8RBtUhy9ioJGV5adQqnHcDkYxRM/ajhPF4KCLSpSqNclZ7jRBmNi48GeDV6CmqaR9CFERzEY/5jn5cDJjskHvmB3O0v2CPZq6EiAQP8r29GBq3RoSjIQCRM0lozGedaXlfWJZq9XAoGGyICeLfLdnbOemRBEreAzhQBdhz1NUygpUU1tI9UaqYy2a8M8hUKsl/AkaMs816iIV6IXfAl5jTbj68S1zgn0pPqDYEPLpjniMAqr6iCmUv07oJJrb3Ybe3oQ+Bb3XKgTQo98s50sBYNw9mOHSTfYxGMCCQXzXUH6lGviy7AW18T0b85RUtWrRCTnH2xKqE/0m70KCkLzNjLJCPuQIkzZ5VraPGKqsWtOt+4aOfwqyY5n7bxl41C7FFlW1Xyl4QGuKOD/BCB3R0gekgXfD9fIKZdany0YhI9DWyWLvzqar0i0e/6t0DborLfLSuDZfbXI7rkcdM76ApC12Io0yo12XxZkgejYeTri3vjMbtKVYZ0R99OikMimPs+GIg5KAB79u0Mj9c3D4/eYw8NpGrlwrpko0sjlC99WZIpJe0tQlNaWKh0lGH29VDCCBUEGCSqGSIb3DQEHAaCCBTIEggUuMIIFKjCCBSYGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAhaEE/1daqfgQICCAAEggTIceK6BIQs8ZhGQ04mZ3BOqELL08KS3sYlGskG4EhCUawbsUI3TXFoXuJV1A9je0uWw2drTdicIK9unJJkxsvNLkJsQnORQBFyNS3XIiRbUrJka7SvF0p7fqB+eVM1jiG1CEP2sQ4uQ0BrtZZ0Aaqv7Pi33OrR/9w79K1iGWYGOD/eqp4UmIPCuFWPJ3zta9iD1lTXhl7FlDBlW6JY1/b5lRqsh2CP4W5rvXvyFoL5XjDHshFVtVC/Z/wKdI5m8zCOh6a/D94gk5qiRYGPqlAra56Sebe7b2a/iDKe2rNqL76DQj2PgeqnrVL95L8lgkDoWD0FUpTt4TwyWiK8DIEwux/MqtYJYuqxHzg1NSalNLBcDN/GDaGB3HkQ7L9Fm6eQnqQUXqJ9UrBy+UqhlnAGagoYrkUkrlzFSGE8CIvBi/L1gSND9dVzi8at5FglA2fV57Xg3McN2h/ox5C/uafFYuoBDrDtNE8J7s6zGGlWwqysuvMnmic5wiu4hHYn6Ydiw/BMfNjlnNSQjis7KDoon9yght7Gaot3Of5fgmJ+sAZSqHsZ3EcgIiEBPLjtMWY+gyOJ3HDhcc3Xobi/aIBfoYKTJR/Uox3oH4wL5iLHbF33aJBDC53Zb6/jxZow1esx+qdf+aXWhto9BPWpl/ZupOLuC5w0QPVmbIniCW3OzywxD1jK2HbNfQvDR+vTVaXCakp8B9dnHnj9I9DQYRdpQ39WmU+vt/x8tNJj31aivIg097YcgKfvfRm1bZ3xk9tKGQvxtftvmZAPN/MCRugptz7UH2QS2hjiOIpAbQHoyLpcLMEeOXokD2ITaYeZRjHe2v/BsWg5nbIb/eknFA5TJb51VJwjJJayrlT+jSvpF4RhNe6xm9I45fUPxfByDibzvAZByfXXLZRccNr0VQxBUIyaIVnqJZjcE+6e5PSc1jmK4qft6U1cwJKJTbcQUOsfW9HYP3705tm1+YN1DcdTrCzBIY6P/YeqYvtWaVoQPKHkWTmitOyvmK7+ebtB+0BU4/kgKzgkg5/Be/6ylGfkGYeKMUwe3Ir/edze55sbDaNHpj/mm2FOimNTS6BPBjjjmSwZYNEInOoVIVBVJ3Gyk9gspoZhOBfZN94+eqaCGjlmN354Sowxn4qYkpG1iU/Ta+1rNQoiGPKpKQw/P10rwss6FqC92OsPVGx0m9ba1lWW4UZKuhSkaYFfQwREt5R4ULdbToUOGVug5dq27rquGaP75E+gRAqVqmNb+oUPUW4qc8+jg3qr9AEulf0iCgTrMKirVAuqVDYTaxDgiDZNSAVZVzM43QRa7eXoX8Q16BU3T2h4Ug2H52vFC8xHARnpKgHO+5IY+Jmcu1CyDZD6sjwrSBSSWSvek+L4/8Wx8/IqyADnifA0VL5BcBIZ0TBn1+J8n72zqyf//Jo8ArsAdXZQjsMlncIj0ExJLz81s2eRurz6zSSCyryZDVp63i4odCrcQEbwtU0AvGToh+juch4JS7lQUuzFdrlmCNVTBLTMVEMUeNDd35a0Jp/n1fDnu5gYfX1JLlcDCEvVgGGXcPk5Naz2KzKCP3L8ghjTUxCNuo9qCIX+NZ0aNkRmDOzdqYbO4XIwpIjxZlVGW79CP4hiK2qjYUWEMSUwIwYJKoZIhvcNAQkVMRYEFE3xOZ+wrYQDW41V+Cj2OUJ6emEQMDEwITAJBgUrDgMCGgUABBTROXmDbpHtaAz/G0iTdJ3JDfw2DAQI59HRQ27QxqYCAggA
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
