import requests
import os
import re

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
# 👇 改这里：允许接收多个 ID，用逗号隔开，留空代表更新默认配置
PROFILE_IDS_STR = os.getenv("CF_PROFILE_IDS", "") 
MODE         = os.getenv("MODE", "exclude")

ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

MAX_RULES       = 4000
TARGET_DOMAIN_N = 0

VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

def get_cn_cidrs():
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    print(f"   IP 数据源获取到 {len(cidrs)} 条 CIDR")
    return cidrs

def get_cn_domains():
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()
    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        line = line.lstrip('.')
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(f"*.{line}")
    unique = list(set(domains))
    print(f"   域名数据源获取到 {len(unique)} 条域名")
    return unique

def update_single_profile(profile_id, cidrs, domains):
    """更新单个配置文件的函数"""
    max_domains = min(TARGET_DOMAIN_N, len(domains))
    max_ips     = min(MAX_RULES - max_domains, len(cidrs))

    domain_entries = [{"host":    d,    "description": "CN Domain"} for d    in domains[:max_domains]]
    ip_entries     = [{"address": cidr, "description": "CN IP"}     for cidr in cidrs[:max_ips]]
    routes = domain_entries + ip_entries

    if len(routes) > MAX_RULES:
        routes = routes[:MAX_RULES]

    # 包含针对 100.100.100.0/24 组网放行的拆分规则
    default_excludes = [
        {"address": "10.0.0.0/8", "description": "Local LAN"},
        {"address": "100.64.0.0/12", "description": "CGNAT (partial)"},
        {"address": "100.80.0.0/13", "description": "CGNAT (partial)"},
        {"address": "100.88.0.0/14", "description": "CGNAT (partial)"},
        {"address": "100.92.0.0/15", "description": "CGNAT (partial)"},
        {"address": "100.94.0.0/16", "description": "CGNAT (partial)"},
        {"address": "100.95.0.0/16", "description": "CGNAT (partial)"},
        {"address": "100.100.101.0/24", "description": "CGNAT (partial)"},
        {"address": "100.100.102.0/23", "description": "CGNAT (partial)"},
        {"address": "100.100.104.0/21", "description": "CGNAT (partial)"},
        {"address": "100.100.112.0/20", "description": "CGNAT (partial)"},
        {"address": "100.100.128.0/17", "description": "CGNAT (partial)"},
        {"address": "100.101.0.0/16", "description": "CGNAT (partial)"},
        {"address": "100.102.0.0/15", "description": "CGNAT (partial)"},
        {"address": "100.104.0.0/13", "description": "CGNAT (partial)"},
        {"address": "100.112.0.0/12", "description": "CGNAT (partial)"},
        {"address": "169.254.0.0/16", "description": "DHCP Unspecified"},
        {"address": "172.16.0.0/12", "description": "Local LAN"},
        {"address": "192.0.0.0/24", "description": "IETF Protocol Assignments"},
        {"address": "192.168.0.0/16", "description": "Local LAN"},
        {"address": "224.0.0.0/24", "description": "Multicast"},
        {"address": "240.0.0.0/4", "description": "Reserved"},
        {"address": "255.255.255.255/32", "description": "DHCP Broadcast"},
        {"address": "fe80::/10", "description": "IPv6 Link Local"},
        {"address": "fd00::/8", "description": "IPv6 Unique Local"},
        {"address": "ff01::/16", "description": "IPv6 Multicast"},
        {"address": "ff02::/16", "description": "IPv6 Multicast"},
        {"address": "ff03::/16", "description": "IPv6 Multicast"},
        {"address": "ff04::/16", "description": "IPv6 Multicast"},
        {"address": "ff05::/16", "description": "IPv6 Multicast"}
    ]
    
    if MODE == "exclude":
        routes.extend(default_excludes)

    # 拼接 API 地址
    if profile_id:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{profile_id}/{MODE}"
        target_name = f"Profile ID: {profile_id}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"
        target_name = "Default Profile"

    print(f"🚀 正在更新: {target_name} | 总路由数: {len(routes)}")
    resp = requests.put(url, json=routes, headers=HEADERS)
    if resp.status_code in (200, 204):
        print(f"✅ 更新成功！")
    else:
        print(f"❌ 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()

if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains()
    
    # 解析环境变量中的多个 ID
    # 如果为空，列表里就放一个空字符串，代表更新默认配置
    if not PROFILE_IDS_STR.strip():
        profile_list = [""]
    else:
        profile_list = [pid.strip() for pid in PROFILE_IDS_STR.split(",") if pid.strip()]
        
    for pid in profile_list:
        update_single_profile(pid, cidrs, domains)
