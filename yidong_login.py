# -*- coding: utf-8 -*-
"""移动云盘(139) 登录与令牌续期 —— 纯标准库实现。

协议按官方 tickstep/cloudpan189-api `AppLogin`（同一套官方登录接口）：
  1) GET  https://cloud.189.cn/unifyLoginForPC.action
         → 取 lt / paramId / reqId / captchaToken / j_rsaKey
  2) POST https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do
         → 账号、密码各自做 RSA(PKCS#1 v1.5) 加密，拼成 "{RSA}" + hex
  3) GET  https://api.cloud.189.cn/getSessionForPC.action
         → 拿 sessionKey
  4) GET  https://api.cloud.189.cn/open/oauth2/getAccessTokenBySsKey.action
         → 拿 sskAccessToken（就是 casgen 里粘贴的那段 Authorization，有效期约 30 天）

★ 更正（2026-11-11）：移动云盘有「旧令牌换新令牌」接口 authTokenRefresh.do ——
移动云盘官方就是这么续的：填一次 Authorization，剩余有效期不足 15 天
时用旧 token 换新 token，不需要密码、不需要扫码、不需要 Cookie。
本模块的账号密码 / Cookie 登录只作兜底，主路径是 refresh_by_token()。
"""

import base64
import hashlib
import http.cookiejar
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

APP_KEY = "8025431004"
WEB_URL = "https://cloud.189.cn"
API_URL = "https://api.cloud.189.cn"
LOGIN_URL = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


class LoginError(Exception):
    """登录失败（密码错 / 风控验证 / 网络异常），message 直接给用户看。"""


# ============================ RSA 加密（PKCS#1 v1.5） ============================
def _tlv(buf, i):
    """极简 DER TLV 解析，返回 (tag, value, 下一个偏移)。"""
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + ln], i + ln


def _parse_pubkey(pem_b64):
    """从 SubjectPublicKeyInfo(base64，无 PEM 头尾) 里取出 (n, e)。"""
    der = base64.b64decode(pem_b64 + "=" * ((-len(pem_b64)) % 4))
    _, spki, _ = _tlv(der, 0)          # SEQUENCE
    _, _, i = _tlv(spki, 0)            # AlgorithmIdentifier
    _, bitstr, _ = _tlv(spki, i)       # BIT STRING
    inner = bitstr[1:]                 # 去掉 unused-bits 字节
    _, rsaseq, _ = _tlv(inner, 0)      # SEQUENCE { INTEGER n, INTEGER e }
    _, nb, j = _tlv(rsaseq, 0)         # INTEGER n
    _, eb, _ = _tlv(rsaseq, j)         # INTEGER e
    return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")


def rsa_encrypt(pem_b64, text):
    """按 PKCS#1 v1.5 加密，返回密文字节。"""
    n, e = _parse_pubkey(pem_b64)
    data = text.encode("utf-8")
    k = (n.bit_length() + 7) // 8
    if len(data) > k - 11:
        raise LoginError("密码过长，无法加密（超过 %d 字节）" % (k - 11))
    pad = bytearray()
    while len(pad) < k - 3 - len(data):
        b = random.getrandbits(8)
        if b:
            pad.append(b)
    em = b"\x00\x02" + bytes(pad) + b"\x00" + data
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")


def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _signature_of_md5(params):
    """等价 Go apiutil.SignatureOfMd5：key=value 排序拼接后取 MD5 小写 hex。"""
    return _md5("&".join(sorted("%s=%s" % (k, v) for k, v in params.items())))


# ============================ 登录主流程 ============================
def _make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def _fetch(opener, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        try:
            return ex.read().decode("utf-8", "replace")
        except Exception:
            raise LoginError("登录接口返回 HTTP %s" % ex.code)
    except Exception as ex:
        raise LoginError("网络异常：%s" % ex)


def app_login(username, password, timeout=25):
    """账号密码登录，返回 dict：
    {token: sskAccessToken, expires_at: 过期时间戳(毫秒), session_key: ...}
    token 可直接当 `Authorization: Basic <token>` 用（与网页粘贴的那段同源）。
    """
    if not username or not password:
        raise LoginError("账号或密码为空")

    opener = _make_opener()

    # 1) 登录页参数
    q = urllib.parse.urlencode({
        "appId": APP_KEY, "clientType": "10020",
        "returnURL": RETURN_URL, "timeStamp": str(int(time.time() * 1000)),
    })
    html = _fetch(opener, WEB_URL + "/unifyLoginForPC.action?" + q, timeout=timeout)

    def grab(pat, name):
        m = re.search(pat, html)
        if not m:
            raise LoginError("登录页缺少参数 %s（页面可能改版，或触发了风控验证）" % name)
        return m.group(1)

    captcha = grab(r"captchaToken' value='(.+?)'", "captchaToken")
    lt = grab(r'lt = "(.+?)"', "lt")
    ret = grab(r"returnUrl = '(.+?)'", "returnUrl")
    param_id = grab(r'paramId = "(.+?)"', "paramId")
    req_id = grab(r'reqId = "(.+?)"', "reqId")
    rsa_key = grab(r'j_rsaKey" value="(.+?)"', "j_rsaKey")

    # 2) 提交账号密码（RSA 加密后转 hex，等价 Go 的 "{RSA}"+B64toHex(Base64(密文))）
    form = {
        "appKey": APP_KEY,
        "accountType": "02",
        "userName": "{RSA}" + rsa_encrypt(rsa_key, username).hex(),
        "password": "{RSA}" + rsa_encrypt(rsa_key, password).hex(),
        "validateCode": "",
        "captchaToken": captcha,
        "returnUrl": ret,
        "mailSuffix": "@189.cn",
        "dynamicCheck": "FALSE",
        "clientType": "10020",
        "cb_SaveName": "1",
        "isOauth2": "false",
        "state": "",
        "paramId": param_id,
    }
    raw = _fetch(opener, LOGIN_URL, data=urllib.parse.urlencode(form).encode("utf-8"),
                 headers={
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Referer": "https://open.e.189.cn/api/logbox/oauth2/unifyAccountLogin.do",
                     "Cookie": "LT=" + lt,
                     "X-Requested-With": "XMLHttpRequest",
                     "REQID": req_id,
                     "lt": lt,
                 }, timeout=timeout)
    try:
        lr = json.loads(raw)
    except Exception:
        raise LoginError("登录返回非 JSON：%s" % raw[:200])
    if str(lr.get("result")) != "0" or not lr.get("toUrl"):
        raise LoginError("登录失败：%s" % (lr.get("msg") or raw[:200]))

    # 3) 换 sessionKey
    s = urllib.parse.urlencode({
        "clientType": "TELEMAC", "version": "1.0.0",
        "channelId": "web_cloud.189.cn", "redirectURL": lr["toUrl"],
    })
    raw = _fetch(opener, API_URL + "/getSessionForPC.action?" + s,
                 headers={"Accept": "application/json;charset=UTF-8"}, timeout=timeout)
    try:
        sr = json.loads(raw)
    except Exception:
        raise LoginError("获取 session 返回非 JSON：%s" % raw[:200])
    session_key = sr.get("sessionKey") or ""
    if str(sr.get("res_code")) != "0" or not session_key:
        raise LoginError("获取 session 失败：%s" % (sr.get("res_message") or raw[:200]))

    # 4) 换 sskAccessToken（真正的 Authorization）
    return _ssk_from_session(session_key, timeout)


def _ssk_from_session(session_key, timeout=25):
    """用 sessionKey 换 sskAccessToken（密码登录与 Cookie 登录共用）。"""
    opener = _make_opener()
    ts = int(time.time() * 1000)
    sign = _signature_of_md5({
        "AppKey": "601102120", "Timestamp": str(ts), "sessionKey": session_key,
    })
    u = API_URL + "/open/oauth2/getAccessTokenBySsKey.action?" + urllib.parse.urlencode(
        {"sessionKey": session_key})
    raw = _fetch(opener, u, headers={
        "AppKey": "601102120", "Signature": sign, "Sign-Type": "1",
        "Accept": "application/json", "Timestamp": str(ts),
    }, timeout=timeout)
    try:
        ar = json.loads(raw)
    except Exception:
        raise LoginError("获取 accessToken 返回非 JSON：%s" % raw[:200])
    token = ar.get("accessToken") or ""
    if not token:
        raise LoginError("获取 accessToken 失败：%s" % raw[:200])

    # expiresIn 可能是「剩余秒数」也可能是「过期时间戳(ms)」，统一折成毫秒时间戳
    exp = ar.get("expiresIn") or 0
    try:
        exp = int(exp)
    except Exception:
        exp = 0
    if exp > 10000000000:              # 已经是毫秒时间戳
        expires_at = exp
    elif exp > 1000000000:             # 秒级时间戳
        expires_at = exp * 1000
    elif exp > 0:                      # 剩余秒数
        expires_at = int(time.time() * 1000) + exp * 1000
    else:
        expires_at = 0

    return {"token": token, "expires_at": expires_at,
            "session_key": session_key, "raw_expires": exp}


def login_by_cookie(cookie, timeout=25):
    """用浏览器 Cookie 换 token —— 免密码、免图形验证码，Cookie 有效期内可反复续期。

    Cookie 来源：浏览器 F12 → Network → 任一 cloud.189.cn 请求 → 请求头 Cookie 整串复制。
    起作用的通常是 COOKIE_LOGIN_USER（有效期很长）。
    """
    cookie = (cookie or "").strip()
    if not cookie:
        raise LoginError("Cookie 为空")
    if cookie.lower().startswith("cookie:"):
        cookie = cookie[7:].strip()
    opener = _make_opener()
    q = urllib.parse.urlencode({
        "clientType": "TELEMAC", "version": "1.0.0",
        "channelId": "web_cloud.189.cn",
        # 必须是 redirect.html 这种形式，否则服务端直接回 analysis redirectURL abnormal
        "redirectURL": "https://cloud.189.cn/web/redirect.html?page=main",
    })
    raw = _fetch(opener, API_URL + "/getSessionForPC.action?" + q,
                 headers={"Cookie": cookie,
                          "Accept": "application/json;charset=UTF-8"}, timeout=timeout)
    try:
        sr = json.loads(raw)
    except Exception:
        raise LoginError("Cookie 换 session 返回异常：%s" % raw[:200])
    session_key = sr.get("sessionKey") or ""
    if not session_key:
        raise LoginError("Cookie 已失效或无效：%s" % (sr.get("res_message") or raw[:160]))
    return _ssk_from_session(session_key, timeout)


# ====== 令牌自续：authTokenRefresh.do 旧令牌换新令牌 ======
REFRESH_URL = "https://aas.caiyun.feixin.10086.cn:443/tellin/authTokenRefresh.do"


def parse_auth(auth):
    """拆开网页粘贴的 Authorization → (前缀, 账号, token, 过期毫秒时间戳)。

    token 形如 xxx|xxx|xxx|<过期时间戳ms>|xxx，第 4 段就是到期时间。
    """
    raw = (auth or "").strip()
    if raw.lower().startswith("basic "):
        raw = raw[6:].strip()
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
    except Exception as e:
        raise LoginError("Authorization 不是合法 base64：%s" % e)
    parts = decoded.split(":")
    if len(parts) < 3:
        raise LoginError("Authorization 格式不对（应为 base64(pc:账号:token)）")
    token = ":".join(parts[2:])
    fields = token.split("|")
    exp = 0
    if len(fields) >= 4:
        try:
            exp = int(fields[3])
        except ValueError:
            exp = 0
    return parts[0], parts[1], token, exp


def refresh_by_token(auth, timeout=25):
    """旧令牌换新令牌：填一次就能一直用，不用密码、不用扫码、不用 Cookie。

    返回 {token: 新的纯 base64 Authorization, expires_at: 毫秒时间戳}。
    """
    prefix, account, token, _ = parse_auth(auth)
    body = ("<root><token>" + token + "</token><account>" + account +
            "</account><clienttype>656</clienttype></root>").encode("utf-8")
    req = urllib.request.Request(REFRESH_URL, data=body, headers={
        "Content-Type": "application/xml",
        "User-Agent": UA,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "ignore")
    except Exception as e:
        raise LoginError("令牌续期请求失败：%s" % e)

    def _tag(name):
        m = re.search(r"<%s>(.*?)</%s>" % (name, name), raw, re.S)
        return m.group(1).strip() if m else ""

    ret, new_token = _tag("return"), _tag("token")
    if ret != "0" or not new_token:
        raise LoginError("令牌续期失败：return=%s desc=%s" %
                         (ret or "?", _tag("desc") or raw[:120]))
    new_auth = base64.b64encode(
        (prefix + ":" + account + ":" + new_token).encode("utf-8")).decode("ascii")
    _, _, _, exp = parse_auth(new_auth)
    if not exp:
        et = _tag("expiretime")
        if et.isdigit():
            v = int(et)
            exp = v if v > 10000000000 else v * 1000
    if not exp:
        exp = int(time.time() * 1000) + 30 * 24 * 3600 * 1000
    return {"token": new_auth, "expires_at": exp,
            "account": account, "raw_expires": exp}


def auth_expires_at(auth):
    """只取令牌里的过期时间戳，解析不出返回 0。"""
    try:
        return parse_auth(auth)[3]
    except Exception:
        return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("用法: python3 yidong_login.py 账号 密码")
        sys.exit(2)
    info = app_login(sys.argv[1], sys.argv[2])
    print("token 前 24 位:", info["token"][:24] + "...")
    if info["expires_at"]:
        print("过期时间:", time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime(info["expires_at"] / 1000)))
    else:
        print("过期时间: 未知（接口未返回）")
