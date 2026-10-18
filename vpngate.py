#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (可本地运行版)
==========================================
流程:
  1. 获取 VPN Gate 原始节点 (官方 API -> GitHub 镜像回退)
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发检测:
       - 若配置了 CHECK_WORKER → 调用 Cloudflare Worker (完整检测)
       - 否则 → 本地 TCP 连通性检测 (无需外部服务)
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt

环境变量 (均可选):
  CHECK_WORKER        检测 Worker 地址 (不填则使用本地 TCP 检测)
  CHECK_CONCURRENCY   并发数 (默认 32)
  CHECK_TIMEOUT       单节点超时秒数 (默认 8 本地 / 90 Worker)
  MAX_CHECK_NODES     最多检测节点数 (0=不限制, 默认 0)
  HTTP_TIMEOUT        下载超时 (默认 60)
  EDGE_HOSTS          静态优选入口 (逗号分隔)
  OPTIMAL_API         优选 API 地址
  PUBLIC_DIR          输出目录 (默认 ./public)
  LOCAL_ONLY          强制使用本地检测 (1/true)
"""

import argparse
import base64
import csv
import io
import json
import os
import re
import socket
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
# 配置
# ---------------------------------------------------------------------------
def env_str(name, default=""):
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def env_num(name, default, cast=int):
    try:
        return cast(env_str(name, str(default)))
    except ValueError:
        return default


def env_bool(name, default=False):
    v = env_str(name, "").lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = env_str("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = env_str(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)


def normalize_worker_url(raw):
    """兼容 Secret 只填域名的情况, 自动补全 scheme / 路径 / 查询参数。"""
    raw = (raw or "").strip()
    if not raw or "你的域名" in raw or "xxx.workers.dev" in raw:
        return ""
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if "sstp=" in parts.query:
        return raw
    path = parts.path.rstrip("/") or "/check"
    return urlunsplit((parts.scheme, parts.netloc, path, "sstp=vpn:vpn@", ""))


WORKER_CHECK_URL = normalize_worker_url(env_str("CHECK_WORKER", ""))
LOCAL_ONLY = env_bool("LOCAL_ONLY", False)
USE_WORKER = bool(WORKER_CHECK_URL) and not LOCAL_ONLY

CONCURRENCY = max(1, env_num("CHECK_CONCURRENCY", 32))
# 本地检测超时默认更短
DEFAULT_TIMEOUT = 90.0 if USE_WORKER else 8.0
CHECK_TIMEOUT = env_num("CHECK_TIMEOUT", DEFAULT_TIMEOUT, float)
MAX_CHECK_NODES = env_num("MAX_CHECK_NODES", 0)
HTTP_TIMEOUT = env_num("HTTP_TIMEOUT", 60)
PUBLIC_DIR = env_str("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASEWEB", "CONTABO",
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

_DEFAULT_EDGE = (
    "saas.sin.fan:443,cdn.204910.best:443,www.mfyx.cn:443,p.etime.vip:443,"
    "cdn.ctn32.us.kg:443,cf.877774.xyz:443,spring.io:443,"
    "cf.nyanya.moe:443,www.sloomb.com:443,op.chinwa.eu.cc:443,"
    "www.leics.police.uk:443,securecircle.com:443,www.shopify.com:443,"
    "www.carousell.sg:443,www.dbs.com.sg:443,openai.com:443,linear.app:443,"
    "www.bilibili.com:443,uspto.gov:443,www.vmware.com:443"
)
EDGE_HOSTS = [h.strip() for h in env_str("EDGE_HOSTS", _DEFAULT_EDGE).split(",") if h.strip()]
OPTIMAL_API = env_str("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443")
NODES_URL = env_str("NODES_URL", "https://J-github-L.github.io/cd/nodes.txt")


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
        if ln.startswith("*"):
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
# 优选 API
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
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
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
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
# 检测逻辑
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


def check_one_local(node):
    """本地 TCP 连通性检测 (不需要 Worker)"""
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    out["mode"] = "local_tcp"

    host = node["host"]
    port = node["port"]
    t0 = time.perf_counter()
    try:
        # 优先用 IP 连接，失败再试域名
        targets = []
        if node.get("ip"):
            targets.append(node["ip"])
        targets.append(host)

        last_err = None
        for target in targets:
            try:
                with socket.create_connection((target, port), timeout=CHECK_TIMEOUT):
                    elapsed_ms = round((time.perf_counter() - t0) * 1000)
                    out["success"] = True
                    out["status"] = "success"
                    out["latency_ms"] = elapsed_ms
                    out["error"] = None
                    out["residential"] = classify_network(host, None, None)
                    return out
            except (socket.timeout, socket.error, OSError) as e:
                last_err = e
                continue

        out["error"] = f"{type(last_err).__name__}: {last_err}" if last_err else "connection failed"
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def check_one_worker(node, session):
    """通过 Cloudflare Worker 检测 (完整信息)"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe=":")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["success"] = False
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    out["mode"] = "worker"

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


def check_one(node, session=None):
    if USE_WORKER and session is not None:
        return check_one_worker(node, session)
    return check_one_local(node)


def check_all(nodes, session=None):
    results = []
    total = len(nodes)
    if total == 0:
        return results
    step = max(1, total // 10)
    mode_name = "Cloudflare Worker" if USE_WORKER else "本地 TCP"
    log("CHECK", f"检测模式: {mode_name} | 并发: {CONCURRENCY} | 超时: {CHECK_TIMEOUT}s")

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        if USE_WORKER:
            futures = [pool.submit(check_one, n, session) for n in nodes]
        else:
            futures = [pool.submit(check_one, n) for n in nodes]

        for i, fut in enumerate(as_completed(futures), 1):
            results.append(fut.result())
            if i % step == 0 or i == total:
                ok = sum(1 for r in results if r.get("success"))
                log("CHECK", f"进度 {i}/{total}, 目前成功 {ok}")
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
        "mode": "worker" if USE_WORKER else "local_tcp",
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


_FALLBACK_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Gate SSTP 节点</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }
  h1 { color: #38bdf8; }
  .card { background: #1e293b; border-radius: 12px; padding: 1.25rem; margin: 1rem 0; }
  .stat { display: inline-block; margin-right: 1.5rem; }
  .stat b { color: #4ade80; font-size: 1.4rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #334155; }
  th { color: #94a3b8; font-weight: 500; }
  .ok { color: #4ade80; }
  .fail { color: #f87171; }
  a { color: #38bdf8; }
</style>
</head>
<body>
  <h1>VPN Gate SSTP 节点</h1>
  <div class="card" id="stats">加载中...</div>
  <div class="card">
    <h2>可用节点</h2>
    <div id="nodes">加载中...</div>
  </div>
  <script>
    fetch('data.json')
      .then(r => r.json())
      .then(d => {
        const s = d.stats;
        document.getElementById('stats').innerHTML = `
          <div class="stat">原始节点 <b>${s.raw_nodes}</b></div>
          <div class="stat">SSTP <b>${s.sstp_nodes}</b></div>
          <div class="stat">检测 <b>${s.checked}</b></div>
          <div class="stat">成功 <b class="ok">${s.success}</b></div>
          <div class="stat">国家/地区 <b>${s.countries}</b></div>
          <div class="stat">模式 <b>${s.mode || '-'}</b></div>
          <p style="margin-top:0.75rem;color:#94a3b8">生成时间: ${d.generated_at} | 来源: ${d.source}</p>
        `;
        const rows = (d.available || []).map(n => `
          <tr>
            <td>${n.country || '-'} (${n.country_code || '?'})</td>
            <td>${n.host}:${n.port}</td>
            <td>${n.latency_ms != null ? n.latency_ms + ' ms' : '-'}</td>
            <td>${n.residential || 'unknown'}</td>
          </tr>`).join('');
        document.getElementById('nodes').innerHTML = rows
          ? `<table><thead><tr><th>国家</th><th>节点</th><th>延迟</th><th>类型</th></tr></thead><tbody>${rows}</tbody></table>`
          : '<p class="fail">暂无可用节点</p>';
      })
      .catch(e => {
        document.getElementById('stats').innerHTML = `<p class="fail">加载失败: ${e}</p>`;
      });
  </script>
</body>
</html>
"""


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


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="VPN Gate SSTP 节点检测流水线")
    parser.add_argument("--local", action="store_true", help="强制使用本地 TCP 检测")
    parser.add_argument("--max", type=int, default=None, help="最多检测节点数")
    parser.add_argument("--concurrency", type=int, default=None, help="并发数")
    parser.add_argument("--timeout", type=float, default=None, help="单节点超时秒数")
    args = parser.parse_args()

    global USE_WORKER, CONCURRENCY, CHECK_TIMEOUT, MAX_CHECK_NODES

    if args.local:
        USE_WORKER = False
    if args.max is not None:
        MAX_CHECK_NODES = args.max
    if args.concurrency is not None:
        CONCURRENCY = max(1, args.concurrency)
    if args.timeout is not None:
        CHECK_TIMEOUT = args.timeout

    if USE_WORKER:
        _u = urlsplit(WORKER_CHECK_URL)
        log("MODE", f"检测模式: Cloudflare Worker → {_u.netloc}{_u.path}")
    else:
        log("MODE", "检测模式: 本地 TCP 连通性检测 (无需 Worker)")
        log("MODE", "提示: 设置环境变量 CHECK_WORKER 可启用完整 Worker 检测")

    session = None
    if USE_WORKER:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=CONCURRENCY, pool_maxsize=CONCURRENCY)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化")

    uniq = dedupe(sstp_nodes)
    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]
        log("VPN GATE", f"已限制检测数量为前 {MAX_CHECK_NODES} 个")

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后待检测: {len(uniq)}")

    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CHECK", f"检测成功: {len(success)}")
    log("CHECK", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CHECK", f"耗时: {elapsed:.1f}s")

    if USE_WORKER and uniq and len(worker_errors) == len(uniq):
        samples = []
        for r in worker_errors:
            e = r.get("error")
            if e not in samples:
                samples.append(e)
            if len(samples) >= 3:
                break
        for e in samples:
            log("DEBUG", f"错误示例: {e}")
        die("Worker 全部请求异常, 检测服务不可用 — 本次不覆盖已有结果")

    # 本地模式下即使没有成功节点也允许生成空结果（方便调试）
    if not success and USE_WORKER:
        die("没有任何可用节点, 本次不覆盖已有结果")

    data = build_outputs(results, raw_count, sstp_count, source)
    edge_hosts = get_combined_edge_hosts()
    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)

    s = data["stats"]
    log("OUTPUT", f"可用节点 {s['success']} / {s['checked']}, 覆盖 {s['countries']} 个国家/地区 "
                  f"(住宅估计 {s['residential_est']}, 机房估计 {s['datacenter_est']})")
    log("OUTPUT", f"已生成: {data_path}")
    log("OUTPUT", f"已生成: {html_path}")
    log("OUTPUT", f"已生成: {nodes_path}")
    log("OUTPUT", f"订阅地址: {NODES_URL}")
    if not success:
        log("OUTPUT", "注意: 本次没有检测到可用节点 (本地模式仍已写出文件)")


if __name__ == "__main__":
    main()
