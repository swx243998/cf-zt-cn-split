import requests
import os
import re
import time

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
# 允许接收多个 ID，用逗号隔开
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
    print("   [1/4] 正在拉取 CN IP 数据源...")
    try:
        r = requests.get(IP_URL, timeout=30)
        r.raise_for_status()
        cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
        print(f"   ✅ 成功获取 {len(cidrs)} 条 IP 网段")
        return cidrs
    except Exception as e:
        print(f"   ❌ 拉取 IP 数据失败: {e}")
        raise

def get_cn_domains():
    print("   [2/4] 正在拉取 CN 域名数据源...")
    try:
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
        print(f"   ✅ 成功获取 {len(unique)} 条合法域名")
        return unique
    except Exception as e:
        print(f"   ❌ 拉取域名数据失败: {e}")
        raise

def update_single_profile(profile_id, cidrs, domains):
    """更新单个配置文件的函数"""
    
    # 区分当前是更新默认还是自定义
    if profile_id:
        target_name = f"自定义配置 (ID: {profile_id})"
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{profile_id}/{MODE}"
    else:
        target_name = "默认配置 (Default)"
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    print(f"\n>>> 开始处理: {target_name}")
    
    max_domains = min(TARGET_DOMAIN_N, len(domains))
    max_ips     = min(MAX_RULES - max_domains, len(cidrs))

    domain_entries = [{"host":    d,    "description": "CN Domain"} for d    in domains[:max_domains]]
    ip_entries     = [{"address": cidr, "description": "CN IP"}     for cidr in cidrs[:max_ips]]
    routes = domain_entries + ip_entries

    if len(routes) > MAX_RULES:
        print(f"   ⚠️ 规则总数 ({len(routes)}) 超出限制，已截断至 {MAX_RULES} 条")
        routes = routes[:MAX_RULES]

    # 包含针对 100.64.0.0/10 默认放行（留给默认设备IP/组网用）
    default_excludes = [
        {"address": "10.0.0.0/8", "description": "Local LAN"},
        {"address": "100.64.0.0/10", "description": "CGNAT"},
        {"address": "169.254.0.0/16", "description": "DHCP Unspecified"},
        {"address": "172.16.0.0/12", "description": "Local LAN"},
        {"address": "192.0.0.0/24", "description": "IETF Protocol Assignments"},
        
        # 👇 以下是 192.168.0.0/16 的拆分，故意去掉了 192.168.100.0/24 用于组网
        {"address": "192.168.0.0/17", "description": "Local LAN (partial)"},
        {"address": "192.168.128.0/18", "description": "Local LAN (partial)"},
        {"address": "192.168.192.0/19", "description": "Local LAN (partial)"},
        {"address": "192.168.224.0/20", "description": "Local LAN (partial)"},
        {"address": "192.168.240.0/21", "description": "Local LAN (partial)"},
        {"address": "192.168.248.0/22", "description": "Local LAN (partial)"},
        {"address": "192.168.252.0/23", "description": "Local LAN (partial)"},
        {"address": "192.168.254.0/24", "description": "Local LAN (partial)"},
        {"address": "192.168.101.0/24", "description": "Local LAN (partial)"},
        {"address": "192.168.102.0/23", "description": "Local LAN (partial)"},
        {"address": "192.168.104.0/21", "description": "Local LAN (partial)"},
        {"address": "192.168.112.0/20", "description": "Local LAN (partial)"},
        # 👆 拆分结束

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
        print(f"   [+] 已追加 {len(default_excludes)} 条局域网/默认保留网段规则（已精准放行 192.168.100.0/24）")

    print(f"   [>] 准备发送 API 请求 (总路由数: {len(routes)})...")
    
    try:
        resp = requests.put(url, json=routes, headers=HEADERS, timeout=30)
        
        # 记录详细的返回状态，方便定位问题
        print(f"   [<] API 响应状态码: {resp.status_code}")
        
        if resp.status_code in (200, 204):
            print(f"   ✅ {target_name} 更新成功！")
        else:
            print(f"   ❌ {target_name} 更新失败！")
            print(f"   ❌ 错误详情: {resp.text}")
            resp.raise_for_status()
    except requests.exceptions.RequestException as e:
         print(f"   ❌ 网络请求异常: {e}")
         raise

if __name__ == "__main__":
    print("========================================")
    print(f"🚀 开始同步 Cloudflare Split Tunnels")
    print(f"   模式 (Mode): {MODE}")
    print(f"   目标账号: {ACCOUNT_ID}")
    print("========================================")
    
    print("🔄 正在准备数据...")
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains()
    
    print("\n[3/4] 正在解析目标配置文件列表...")
    # 1. 强制把“默认配置”放进列表里（空字符串代表默认）
    profile_list = [""]
    
    # 2. 解析环境变量里的自定义配置
    if PROFILE_IDS_STR.strip():
        custom_ids = [pid.strip() for pid in PROFILE_IDS_STR.split(",") if pid.strip()]
        profile_list.extend(custom_ids)
        print(f"   ✅ 解析到 {len(custom_ids)} 个自定义 ID")
    else:
        print("   ℹ️ 未发现自定义 ID，将只更新默认配置")
    
    print(f"   📋 最终更新队列: {len(profile_list)} 个配置")
    
    print("\n[4/4] 开始执行更新 API 操作...")
    # 循环更新
    for pid in profile_list:
        update_single_profile(pid, cidrs, domains)
        
    print("\n========================================")
    print("🎉 所有配置更新流程执行完毕！")
    print("========================================")
