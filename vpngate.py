#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (修正版)
=====================================
流程:
  1. 获取 VPN Gate 原始节点 (官方 API -> GitHub 镜像回退)
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt

必填环境变量:
  CHECK_WORKER   检测 Worker 地址, 形如 https://xxx.workers.dev/check?sstp=vpn:vpn@
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 配置 (空字符串环境变量 -> 使用默认值, 避免 GitHub Actions 空 Secret 导致报错)
# ---------------------------------------------------------------------------
def env_str(name, default=""):
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def env_num(name, default, cast=int):
    try:
        return cast(env_str(name, str(default)))
    except ValueError:
        return default


REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = env_str("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = env_str(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)


def normalize_worker_url(raw):
    """兼容 Secret 只填域名的情况, 自动补全 scheme / 路径 / 查询参数。

    支持:  xxx.workers.dev
           https://xxx.workers.dev
           https://xxx.workers.dev/check
           https://xxx.workers.dev/check?sstp=vpn:vpn@   (完整, 原样使用)
    """
    raw = raw.strip()
    if "你的域名" in raw or not raw:
        return raw
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if "sstp=" in parts.query:
        return raw
    path = parts.path.rstrip("/") or "/check"
    return urlunsplit((parts.scheme, parts.netloc, path, "sstp=vpn:vpn@", ""))


URL_SAFE = ":"  # 预检时会自动确定 (":" 或 "")
WORKER_CHECK_URL = normalize_worker_url(env_str("CHECK_WORKER", "https://你的域名/check?sstp=vpn:vpn@"))
CONCURRENCY = max(1, env_num("CHECK_CONCURRENCY", 32))
CHECK_TIMEOUT = env_num("CHECK_TIMEOUT", 90.0, float)
MAX_CHECK_NODES = env_num("MAX_CHECK_NODES", 0)
HTTP_TIMEOUT = env_num("HTTP_TIMEOUT", 60)
PUBLIC_DIR = env_str("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 静态优选域名池
_DEFAULT_EDGE = (
    "saas.sin.fan:443,cdn.204910.best:443,www.mfyx.cn:443,p.etime.vip:443,"
    "cdn.ctn32.us.kg:443,cf.877774.xyz:443,spring.io:443,"
    "cf.nyanya.moe:443,www.sloomb.com:443,op.chinwa.eu.cc:443,"
    "www.leics.police.uk:443,securecircle.com:443,www.shopify.com:443,"
    "www.carousell.sg:443,www.dbs.com.sg:443,openai.com:443,linear.app:443,"
    "www.bilibili.com:443,uspto.gov:443,www.vmware.com:443"
)
EDGE_HOSTS = [h.strip() for h in env_str("EDGE_HOSTS", _DEFAULT_EDGE).split(",") if h.strip()]

# 优选 API 地址 (逗号分隔可多个)
OPTIMAL_API = env_str("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443")

def _default_nodes_url():
    """在 GitHub Actions 中按 GITHUB_REPOSITORY 自动生成 Pages 订阅地址"""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        return f"https://{owner.lower()}.github.io/{name}/nodes.txt"
    return "https://YOUR_GITHUB_USERNAME.github.io/YOUR_REPO/nodes.txt"


NODES_URL = env_str("NODES_URL", _default_nodes_url())


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========", flush=True)
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(
            VPNGATE_API, timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
        )
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
        log("VPN GATE", "镜像返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")


def parse_csv(text):
    text = text.lstrip("\ufeff")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#*").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = next(csv.reader([lines[header_idx].lstrip("#*")]))
    data_lines = lines[header_idx + 1:]

    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*#").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }
    need = max(pos.values()) + 1

    rows = []
    for ln in data_lines:
        if ln.startswith("*"):  # 结尾的 "*" 标记行
            continue
        try:
            fields = next(csv.reader(io.StringIO(ln)))
        except (StopIteration, csv.Error):
            continue
        if len(fields) < need:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        if not isinstance(s, dict):
            continue
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """拉取优选 API, 解析 `172.66.1.179:443#CF 电信优选` 格式, 提取 IP:端口"""
    if not api_urls_str.strip():
        return []

    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
                continue
            count = 0
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                endpoint = line.split("#")[0].strip()
                if not endpoint:
                    continue
                if ":" not in endpoint:
                    endpoint = f"{endpoint}:443"
                endpoints.append(endpoint)
                count += 1
            log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints


def get_combined_edge_hosts():
    """合并静态优选域名与优选 API 端点 (去重, 保序)"""
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    combined, seen = [], set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL",
        f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined or list(EDGE_HOSTS)


# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host, "port": port, "ip": r["ip"],
            "country": r["country_long"], "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    seen, out = set(), []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"


def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe=URL_SAFE)
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"

    # Worker 层面的异常 (网络错误 / 非 200) 重试一次
    j = None
    for attempt in range(2):
        try:
            r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
            if r.status_code != 200:
                out["error"] = f"HTTP {r.status_code}"
                out["worker_error"] = True
                continue
            try:
                j = r.json()
            except ValueError:
                snippet = " ".join((r.text or "").split())[:150]
                ctype = r.headers.get("Content-Type", "?")
                out["error"] = f"响应不是 JSON (HTTP {r.status_code}, {ctype}): {snippet or '<空>'}"
                out["worker_error"] = True
                j = None
                continue
            if not isinstance(j, dict):
                out["error"] = "Worker 返回了非 JSON 对象"
                out["worker_error"] = True
                j = None
                continue
            out.pop("worker_error", None)
            break
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
            out["worker_error"] = True
            j = None
    if j is None:
        return out

    ok = bool(j.get("success"))
    out["success"] = ok
    out["status"] = "success" if ok else "failed"
    out["latency_ms"] = j.get("responseTime")
    out["colo"] = j.get("colo")
    out["error"] = None if ok else (j.get("error") or j.get("message") or "check failed")

    exit_info = j.get("exit")
    if isinstance(exit_info, dict) and exit_info:
        asn = exit_info.get("asn")
        if not isinstance(asn, dict):
            asn = {"asn": asn} if asn else {}
        org = asn.get("org") or asn.get("name") or ""
        out["exit"] = {
            "ip": exit_info.get("ip"),
            "country": exit_info.get("country"),
            "country_code": exit_info.get("country_code"),
            "city": exit_info.get("city"),
            "continent": exit_info.get("continent"),
            "asn": asn.get("asn"),
            "org": org,
            "type": asn.get("type"),
            "is_datacenter": exit_info.get("is_datacenter"),
        }
        out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
    else:
        out["residential"] = classify_network(out["host"], None, None)
    return out


def check_all(nodes, session):
    results = []
    total = len(nodes)
    step = max(1, total // 10)
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for i, fut in enumerate(as_completed(futures), 1):
            results.append(fut.result())
            if i % step == 0 or i == total:
                ok = sum(1 for r in results if r.get("success"))
                log("CLOUDFLARE WORKER", f"进度 {i}/{total}, 目前成功 {ok}")
    return results


# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n.get("country") or "未知"
        countries.setdefault(c, {"code": n.get("country_code") or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }


def build_nodes_text(data, edge_hosts):
    """纯节点行 (无注释): 每行 = 入口地址#名字$sstp://..."""
    if not edge_hosts:
        edge_hosts = list(EDGE_HOSTS)
    if not edge_hosts:
        raise RuntimeError("入口地址池为空, 无法生成 nodes.txt")

    lines, idx = [], 0
    ordered = sorted(
        data["countries"].items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for label, group in (("住宅", res_nodes), ("机房", dc_nodes)):
            for i, n in enumerate(group, 1):
                entry = edge_hosts[idx % len(edge_hosts)]
                idx += 1
                lines.append(f"{entry}#{zh}-{label}-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


_FALLBACK_HTML = (
    "<!doctype html><html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
    "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre>"
    "<script>fetch('data.json').then(r=>r.json())"
    ".then(d=>{document.getElementById('out').textContent=JSON.stringify(d.stats,null,2)})"
    ".catch(e=>{document.getElementById('out').textContent='加载失败: '+e})</script>"
    "</body></html>"
)


def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = _FALLBACK_HTML
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data, edge_hosts))

    return data_path, html_path, nodes_path


def preflight(session, node):
    """正式检测前先探测 Worker: 打印原始响应, 并自动选择可用的 URL 编码方式"""
    global URL_SAFE
    target = f"{node['host']}:{node['port']}"
    for safe in (":", ""):
        url = WORKER_CHECK_URL + quote(target, safe=safe)
        try:
            r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        except Exception as exc:
            log("PREFLIGHT", f"safe={safe!r}: 请求失败 {type(exc).__name__}: {str(exc)[:200]}")
            continue
        snippet = " ".join((r.text or "").split())[:200]
        log("PREFLIGHT",
            f"safe={safe!r}: HTTP {r.status_code}, Content-Type={r.headers.get('Content-Type', '?')}, "
            f"Server={r.headers.get('Server', '?')}, 正文: {snippet or '<空>'}")
        try:
            j = r.json()
        except ValueError:
            continue
        if isinstance(j, dict):
            URL_SAFE = safe
            log("PREFLIGHT", f"Worker 返回 JSON 正常 (字段: {', '.join(list(j.keys())[:12])})")
            return True
    return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    if "你的域名" in WORKER_CHECK_URL or not WORKER_CHECK_URL.startswith(("http://", "https://")):
        die("未配置检测 Worker: 请设置环境变量 CHECK_WORKER, "
            "例如 https://xxx.workers.dev/check?sstp=vpn:vpn@")

    _u = urlsplit(WORKER_CHECK_URL)
    log("CLOUDFLARE WORKER", f"检测接口: <域名已隐藏>{_u.path}?{_u.query}<节点>")

    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=CONCURRENCY, pool_maxsize=CONCURRENCY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    if not preflight(session, uniq[0]):
        die("Worker 预检失败: 返回的不是 JSON。请对照上方 PREFLIGHT 日志: "
            "HTML/首页 => 路径不对(把 Secret 改成完整的 .../check?sstp=vpn:vpn@); "
            "403/Just a moment => 被 Cloudflare 防护拦截; 404 => 路由或域名绑定有误; "
            "<空> => Worker 代码异常")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER",
        f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and len(worker_errors) == len(uniq):
        samples = []
        for r in worker_errors:
            e = r.get("error")
            if e not in samples:
                samples.append(e)
            if len(samples) >= 3:
                break
        log("DEBUG", f"Worker 请求示例: {WORKER_CHECK_URL.split('?')[0]}?... + {worker_errors[0]['host']}:{worker_errors[0]['port']}")
        for e in samples:
            log("DEBUG", f"错误示例: {e}")
        die("Worker 全部请求异常, 检测服务不可用 — 本次不覆盖已有结果")
    if not success:
        die("没有任何可用节点, 本次不覆盖已有结果")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    # 动态拉取 API 并与静态优选域名混合
    edge_hosts = get_combined_edge_hosts()

    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
