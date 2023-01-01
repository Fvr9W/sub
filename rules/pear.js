/*
app下载地址：https://t.cn/A6htR2an

#圈Xpear解锁会员
^https:\/\/ayk\.tmdidi\.com\/(api\/movie\/WatchMovie|api\/Account\/CheckVip|api\/account\/IndexDetail) url script-response-body pear.js

MITM = m.pearkin.com

*/

var body = $response.body;
var url = $request.url;
var obj = JSON.parse(body);

const vip = '/api/movie/WatchMovie';

const checkvip = '/api/Account/CheckVip';

const vipinfo = '/api/account/IndexDetail';

const jf = '/api/account/UserScore';

if (url.indexOf(vip) != -1) {
	obj["canWath"] = "true";
	obj["hadWach"] = "true";
	obj["surplusCount"] = "999";
	body = JSON.stringify(obj);
 }

if (url.indexOf(checkvip) != -1) {
	obj["data"] = "1";
   obj["value"] = "true";
	body = JSON.stringify(obj);
 }
if (url.indexOf(vipinfo) != -1) {
	obj["nickName"] = "解锁";
   obj["vipLevel"] = "100";
   obj["vipEndTime"] = "2099-11-11";
   obj["cartoonVip"] = "true";
	body = JSON.stringify(obj);
 }
if (url.indexOf(jf) != -1) {
	obj["value"] = "99999";
	body = JSON.stringify(obj);
 }

$done({body});
