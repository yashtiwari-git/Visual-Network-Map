#!/usr/bin/env python3
"""
FINAL — Active-only Home Network Mapper (alive devices only, type-labelled)
- nmap ARP baseline
- ping sweep (concurrent) -> returns alive IPs
- read ARP table
- tshark passive capture
- optional nmap -O/-sV probes to improve type guesses
- outputs: network.json (nodes+edges) with labels like "Laptop 101", unknown_ouis.txt, and console summary
Run as Administrator: python scan.py
"""
import subprocess, platform, re, json, xml.etree.ElementTree as ET, time, os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------- Config -----------------
TSHARK_DURATION = 90   # seconds
PING_WORKERS = 80
PING_TIMEOUT_MS = 700
NMAP_PROBE_WORKERS = 6
NMAP_PROBE_TIMEOUT = 35
NMAP_PROBE_PORTS = "22,53,80,139,445,443,5353,1900,8008,8080,8888"
BROADCAST_PREFIXES = ("224.", "239.", "255.")
# ------------------------------------------------------------------

# ----------------- heuristics / mappings ---------------------------
VENDOR_TYPE = {
    "APPLE": "phone", "SAMSUNG": "phone", "HONOR": "phone", "XIAOMI": "phone",
    "ONEPLUS": "phone", "LG": "smart tv", "SONY": "smart tv", "DELL": "laptop",
    "LENOVO": "laptop", "HP": "laptop", "RASPBERRY": "nas", "INTEL": "pc",
}
OUI_TYPE = {
    "3C0754": "phone", "F01898": "tablet", "AC1F6B": "laptop",
    "001A11": "smart tv", "28C68E": "smart tv", "B827EB": "nas", "DC0D30": "laptop",
}
HOSTNAME_KEYWORDS = {
    "android":"phone","pixel":"phone","oneplus":"phone","galaxy":"phone",
    "iphone":"phone","ipad":"tablet","tablet":"tablet",
    "tv":"smart tv","smart-tv":"smart tv","chromecast":"smart tv",
    "roku":"smart tv","firetv":"smart tv","stick":"smart tv",
    "raspberry":"nas","pi-":"nas","nas":"nas",
    "laptop":"laptop","macbook":"laptop","imac":"laptop","desktop":"pc",
}
OS = platform.system()
# ------------------------------------------------------------------

def now(): return datetime.now().strftime('%H:%M:%S')

def get_default_gateway():
    try:
        if OS.startswith("Windows"):
            out = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
            m = re.search(r"Default Gateway[\. ]*: (\d+\.\d+\.\d+\.\d+)", out)
            if m: return m.group(1)
            out = subprocess.check_output("route PRINT 0.0.0.0", shell=True, text=True, errors="ignore")
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
            if m: return m.group(1)
        else:
            out = subprocess.check_output("ip route", shell=True, text=True, errors="ignore")
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m: return m.group(1)
    except Exception:
        pass
    return "192.168.1.1"

def base_subnet(gateway):
    p = gateway.split('.')
    return f"{p[0]}.{p[1]}.{p[2]}.0/24"

# ----------------- Nmap baseline -------------------------------
def run_nmap(subnet):
    cmd = ["nmap","-sn","-PR","-n","-oX","-",subnet]
    print(f"[{now()}] Running nmap ARP scan...")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print("nmap failed:", proc.stderr.strip())
        return ""
    return proc.stdout

def parse_nmap_xml(xml_text):
    hosts=[]
    if not xml_text: return hosts
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up": continue
        ip=None; mac=""; vendor=""
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t=="ipv4": ip=addr.get("addr")
            elif t=="mac": mac=addr.get("addr").upper(); vendor=addr.get("vendor") or ""
        hn=""
        hnames=host.find("hostnames")
        if hnames is not None:
            hn_el=hnames.find("hostname")
            if hn_el is not None: hn = hn_el.get("name") or ""
        if ip: hosts.append({"ip":ip,"mac":mac,"vendor":vendor,"hostname":hn})
    return hosts

# ----------------- ping sweep (returns alive IPs) ----------------
def ping_one(ip):
    try:
        if OS.startswith("Windows"):
            cmd = f"ping -n 1 -w {PING_TIMEOUT_MS} {ip}"
        else:
            cmd = f"ping -c 1 -W 1 {ip}"
        res = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except:
        return False

def ping_sweep(ip_list, workers=PING_WORKERS):
    """
    Returns set of IPs that responded to ping. Non-blocking/parallel.
    """
    alive = set()
    print(f"[{now()}] Running ping sweep on {len(ip_list)} IPs (workers={workers}) ...")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping_one, ip): ip for ip in ip_list}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                alive.add(ip)
    print(f"[{now()}] Ping sweep done. {len(alive)} responded to ping.")
    return alive

# ----------------- ARP table read --------------------------------
def read_arp_table():
    mappings = {}
    try:
        if OS.startswith("Windows"):
            out = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-:]{12,17})\s+\w+", line.strip())
                if m:
                    mappings[m.group(1)] = m.group(2).replace("-",":").upper()
        else:
            try:
                out = subprocess.check_output("ip neigh", shell=True, text=True, errors="ignore")
                for line in out.splitlines():
                    mm = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})", line, re.I)
                    if mm: mappings[mm.group(1)] = mm.group(2).upper()
            except Exception:
                pass
            try:
                out = subprocess.check_output("arp -n", shell=True, text=True, errors="ignore")
                for line in out.splitlines():
                    mm = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})", line, re.I)
                    if mm: mappings[mm.group(1)] = mm.group(2).upper()
            except Exception:
                pass
    except Exception:
        pass
    return mappings

# ----------------- tshark listener --------------------------------
def run_tshark_listen(duration=TSHARK_DURATION, iface=None):
    fields=["arp.src.proto_ipv4","arp.src.hw_mac","bootp.option.hostname","dhcp.option.hostname","ip.src","eth.src","dns.qry.name","mdns.resp.name"]
    filter_expr = "arp || bootp || dhcp || mdns || nbns || dns"
    cmd = ["tshark","-Y",filter_expr,"-a",f"duration:{duration}","-T","fields"]
    for f in fields: cmd += ["-e", f]
    cmd += ["-E","separator=|","-E","occurrence=f"]
    if iface:
        cmd = ["tshark","-i",iface,"-Y",filter_expr,"-a",f"duration:{duration}","-T","fields"]
        for f in fields: cmd += ["-e", f]
        cmd += ["-E","separator=|","-E","occurrence=f"]
    print(f"[{now()}] Running tshark for {duration}s (requires tshark in PATH).")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[WARN] tshark not found in PATH; skipping passive capture.")
        return set()
    results=set()
    for ln in proc.stdout.splitlines():
        parts = ln.split("|")
        arp_ip = parts[0].strip() if len(parts)>0 else ""
        arp_mac = parts[1].strip() if len(parts)>1 else ""
        bootp = parts[2].strip() if len(parts)>2 else ""
        dhcpn = parts[3].strip() if len(parts)>3 else ""
        ip_src = parts[4].strip() if len(parts)>4 else ""
        eth_src = parts[5].strip() if len(parts)>5 else ""
        dns_qry = parts[6].strip() if len(parts)>6 else ""
        mdns_n = parts[7].strip() if len(parts)>7 else ""
        ip = arp_ip or ip_src or ""
        mac = arp_mac or eth_src or ""
        hostname = bootp or dhcpn or dns_qry or mdns_n or ""
        if ip:
            results.add((ip, mac.upper() if mac else "", hostname))
    return results

# ----------------- nmap probe functions (optional) ----------------
def run_nmap_os_probe(ip, extra_args=None, timeout=NMAP_PROBE_TIMEOUT):
    args = ["nmap","-O","-sV","-p",NMAP_PROBE_PORTS,"-Pn","-oX","-",ip]
    if extra_args: args = extra_args + args
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0 and not proc.stdout: return None
        root = ET.fromstring(proc.stdout)
        host = root.find("host")
        if host is None: return None
        probe = {"ip":ip,"os":None,"os_accuracy":None,"services":[]}
        os_el = host.find("os")
        if os_el is not None:
            osm = os_el.find("osmatch")
            if osm is not None:
                probe["os"] = osm.get("name"); probe["os_accuracy"] = osm.get("accuracy")
        for port in host.findall(".//port"):
            service = port.find("service")
            if service is not None:
                probe["services"].append({
                    "port": port.get("portid"),
                    "name": service.get("name") or "",
                    "product": service.get("product") or "",
                    "version": service.get("version") or ""
                })
        return probe
    except Exception:
        return None

OS_SERVICE_KEYWORDS = {
    "android":"phone","ios":"phone","darwin":"laptop","mac os":"laptop",
    "linux":"device","openwrt":"router","routeros":"router","raspbian":"nas",
    "raspberry":"nas","chromecast":"smart tv","roku":"smart tv",
    "amazon":"smart tv","synology":"nas","qnap":"nas",
}

def infer_type_from_probe(probe):
    if not probe: return None
    os_str = (probe.get("os") or "").lower()
    for k,t in OS_SERVICE_KEYWORDS.items():
        if k in os_str: return t
    for s in probe.get("services",[]):
        prod = (s.get("product") or "").lower()
        name = (s.get("name") or "").lower()
        if "samba" in name or "microsoft-ds" in name: return "pc"
        if "airplay" in prod or "apple" in prod: return "phone"
        if "synology" in prod or "diskstation" in prod: return "nas"
    return None

def probe_ips_with_nmap(ip_list, workers=NMAP_PROBE_WORKERS, timeout_per_ip=NMAP_PROBE_TIMEOUT):
    results={}
    if not ip_list: return results
    print(f"[{now()}] Running nmap OS/service probes on {len(ip_list)} hosts ...")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(run_nmap_os_probe, ip, None, timeout_per_ip): ip for ip in ip_list}
        for fut in as_completed(futures):
            ip = futures[fut]
            try: r = fut.result()
            except: r = None
            if r: results[ip]=r
    print(f"[{now()}] Nmap probes completed: {len(results)} results.")
    return results

# ----------------- heuristics helpers --------------------------------
def mac_to_type(mac):
    if not mac: return "device"
    clean = mac.replace(":","").replace("-","").upper()
    return OUI_TYPE.get(clean[:6],"device")

def vendor_to_type(vendor, mac):
    if vendor:
        v = vendor.upper()
        for key,t in VENDOR_TYPE.items():
            if key in v: return t
    return mac_to_type(mac)

def hostname_to_type(hostname):
    if not hostname: return None
    h = hostname.lower()
    for kw,t in HOSTNAME_KEYWORDS.items():
        if kw in h: return t
    return None

# ----------------- build payload (alive-only + smart labels) -----------
def build_payload(nmap_hosts, tshark_records, arp_map, gateway, ping_alive_set):
    """
    Build info merged, then keep ONLY alive devices:
    alive IPs = nmap_hosts (nmap up) U ping_alive_set U tshark observed IPs
    Node labels: "<Type> <last-octet>" e.g. "Laptop 101"
    """
    info={}
    unknown_ouis=set()

    # baseline from nmap
    nmap_ips = set()
    for h in nmap_hosts:
        ip=h["ip"]; nmap_ips.add(ip)
        mac=h.get("mac","") or ""; vendor=h.get("vendor","") or ""; hn=h.get("hostname","") or ""
        if (not mac) and (ip in arp_map): mac = arp_map[ip]
        dtype = vendor_to_type(vendor, mac)
        if dtype == "device" and mac:
            unknown_ouis.add(mac.replace(":","").replace("-","").upper()[:6])
        info[ip] = {"ip":ip,"mac":mac,"dtype":dtype,"vendor":vendor,"hostnames": set([hn]) if hn else set()}

    # add ARP entries
    for ip, mac in arp_map.items():
        if ip not in info:
            dtype = vendor_to_type("", mac)
            if dtype == "device" and mac:
                unknown_ouis.add(mac.replace(":","").replace("-","").upper()[:6])
            info[ip] = {"ip":ip,"mac":mac,"dtype":dtype,"vendor":"","hostnames": set()}

    # add tshark records
    tshark_ips = set()
    for rec in tshark_records:
        ip=rec[0]; mac=rec[1] if len(rec)>1 else ""; hn=rec[2] if len(rec)>2 else ""
        if ip:
            tshark_ips.add(ip)
            if ip in info:
                if not info[ip]["mac"] and mac: info[ip]["mac"]=mac; info[ip]["dtype"]=vendor_to_type(info[ip]["vendor"], mac)
                if hn: info[ip]["hostnames"].add(hn)
            else:
                dtype = vendor_to_type("", mac)
                if dtype=="device" and mac: unknown_ouis.add(mac.replace(":","").replace("-","").upper()[:6])
                info[ip] = {"ip":ip,"mac":mac,"dtype":dtype,"vendor":"","hostnames": set([hn]) if hn else set()}

    # refine using hostnames
    for ip, data in info.items():
        for hn in list(data.get("hostnames", [])):
            t = hostname_to_type(hn)
            if t:
                data["dtype"] = t
                if data.get("mac"):
                    clean = data["mac"].replace(":","").replace("-","").upper()[:6]
                    if clean in unknown_ouis: unknown_ouis.discard(clean)

    # determine alive set (only these will be shown)
    alive_ips = set()
    alive_ips.update(nmap_ips)
    alive_ips.update(ping_alive_set or [])
    alive_ips.update(tshark_ips)
    # filter reserved/multicast
    alive_ips = {ip for ip in alive_ips if not (ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255.") or ip.endswith(".255") or ip=="0.0.0.0")}
    # ensure gateway/router is included
    alive_ips.add(gateway)

    # OPTIONAL: run nmap OS probes on alive IPs (except gateway) to improve dtype
    probe_candidates = [ip for ip in alive_ips if ip != gateway]
    if probe_candidates:
        probe_results = probe_ips_with_nmap(probe_candidates, workers=NMAP_PROBE_WORKERS, timeout_per_ip=NMAP_PROBE_TIMEOUT)
        for ip, probe in probe_results.items():
            guessed = infer_type_from_probe(probe)
            if guessed and ip in info: info[ip]["dtype"] = guessed

    # Now build nodes/edges using only alive IPs, label as "<Type> <last-octet>"
    nodes = []; edges = []; node_id = 1
    nodes.append({"id": node_id, "label": "Router", "ip": gateway, "mac": info.get(gateway,{}).get("mac",""), "type":"router"})
    router_id = node_id; node_id += 1

    # keep consistent ordering by IP
    for ip in sorted(alive_ips, key=lambda x: list(map(int, x.split('.')))):
        if ip == gateway: continue
        if ip not in info:
            # still create a minimal entry
            info[ip] = {"ip":ip,"mac": arp_map.get(ip,""), "dtype":"device", "vendor": "", "hostnames": set()}
        d = info[ip]
        # compute label type and suffix (use last octet as suffix)
        last = ip.split('.')[-1]
        t = d.get("dtype","device").capitalize()
        label = f"{t} {last}"
        nodes.append({"id":node_id,"label":label,"ip":ip,"mac":d.get("mac",""),"type":d.get("dtype","device")})
        edges.append({"from":router_id,"to":node_id})
        node_id += 1

    # print summary
    print("\n=== Active Device Summary ===")
    header = f"{'IP Address':<16} {'MAC':<20} {'Hostnames':<30} {'Type'}"
    print(header); print("-"*len(header))
    for ip in sorted(alive_ips, key=lambda x: list(map(int, x.split('.')))):
        d = info.get(ip, {})
        mac = d.get("mac","-") or "-"
        hn = ", ".join(sorted(d.get("hostnames",[]))) if d.get("hostnames") else "-"
        print(f"{ip:<16} {mac:<20} {hn:<30} {d.get('dtype','device')}")
    print("-"*len(header))
    print(f"Active devices (including router): {len(nodes)}\n")

    return {"nodes":nodes,"edges":edges}, unknown_ouis

# ----------------- main flow ----------------------------------------
def main():
    gateway = get_default_gateway()
    subnet = base_subnet(gateway)
    print(f"[{now()}] Gateway: {gateway}  Subnet: {subnet}")

    # 1) nmap baseline
    nmap_hosts=[]
    try:
        xml = run_nmap(subnet)
        nmap_hosts = parse_nmap_xml(xml)
        print(f"[{now()}] nmap found {len(nmap_hosts)} hosts (up).")
    except Exception as e:
        print("nmap step failed:", e)
        nmap_hosts = []

    # prepare ip list for ping sweep (nmap discovered or fallback full /24)
    ip_list = [h["ip"] for h in nmap_hosts]
    if not ip_list:
        p = gateway.split('.'); base = '.'.join(p[:3])
        ip_list = [f"{base}.{i}" for i in range(1,255)]

    # 2) ping sweep -> get alive set
    ping_alive = ping_sweep(ip_list, workers=PING_WORKERS)

    # 3) read ARP table
    arp_map = read_arp_table()
    print(f"[{now()}] ARP table entries found: {len(arp_map)}")

    # 4) tshark capture (passive)
    tshark_records = run_tshark_listen(duration=TSHARK_DURATION)
    print(f"[{now()}] tshark discovered {len(tshark_records)} records.")

    # 5) build payload (alive-only)
    payload, unknown_ouis = build_payload(nmap_hosts, tshark_records, arp_map, gateway, ping_alive)

    # 6) write network.json
    with open("network.json","w") as f:
        json.dump(payload, f, indent=2)
    print(f"[{now()}] network.json written. Nodes: {len(payload['nodes'])}")

    # 7) write unknown_ouis
    if unknown_ouis:
        with open("unknown_ouis.txt","w") as uf:
            for o in sorted(unknown_ouis): uf.write(o+"\n")
        print(f"[{now()}] Unknown OUI prefixes written: {len(unknown_ouis)}")
    else:
        try:
            if os.path.exists("unknown_ouis.txt"): os.remove("unknown_ouis.txt")
        except: pass

if __name__=="__main__":
    main()
