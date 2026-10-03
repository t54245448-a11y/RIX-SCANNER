#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
██████╗ ██╗██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗
██╔══██╗██║╚██╗██╔╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗
██████╔╝██║ ╚███╔╝     ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝
██╔══██╗██║ ██╔██╗     ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗
██║  ██║██║██╔╝╚██╗    ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝

RIX SCANNER v11.0 — Ultimate CDN IP Scanner
IPv4 + IPv6 | Real TLS/SNI | CIDR Detection | NET-MELI | Multi-CDN
Personal Use Only | github.com/t54245448-a11y/RIX-SCANNER
"""

import socket,ssl,ipaddress,random,time,sys,os,threading,json,csv
import urllib.request
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timedelta

# ── Colors ─────────────────────────────────────────────────────────
R="\033[1;31m";G="\033[1;32m";Y="\033[1;33m";B="\033[1;34m"
M="\033[1;35m";C="\033[1;36m";W="\033[1;37m";DIM="\033[2m"
RST="\033[0m";BLD="\033[1m";GR="\033[2;32m";CY="\033[0;36m"
O="\033[38;5;208m"   # orange
P="\033[38;5;135m"   # purple

# ══════════════════════════════════════════════════════════════════
#  CIDR DATA
# ══════════════════════════════════════════════════════════════════

CF_CIDRS_V4 = [
    "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
    "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15",
    "172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
    "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
]

CF_CIDRS_V6 = [
    "2606:4700::/32",
    "2606:4700:3000::/48","2606:4700:3001::/48","2606:4700:3002::/48",
    "2606:4700:3003::/48","2606:4700:3004::/48","2606:4700:3005::/48",
    "2606:4700:3006::/48","2606:4700:3007::/48",
    "2400:cb00::/32","2803:f800::/32","2c0f:f248::/32","2a06:98c0::/29",
]

CF_IRAN_FAST_V4 = [
    "104.16.0.0/13","104.24.0.0/14","172.64.0.0/13",
    "162.158.0.0/15","188.114.96.0/20","190.93.240.0/20",
]
CF_IRAN_FAST_V6 = [
    "2606:4700::/32","2606:4700:3000::/48","2606:4700:3001::/48",
]

MULTI_CIDRS = {
    "Fastly"    :{"v4":["151.101.0.0/16","199.232.0.0/16","23.235.32.0/20","199.27.72.0/21"],"v6":["2a04:4e40::/32","2a04:4e41::/32","2a04:4e42::/32"]},
    "Gcore"     :{"v4":["92.223.64.0/18","109.200.208.0/21","185.18.208.0/22"],"v6":["2a03:90c0::/32","2a03:90c1::/32"]},
    "Bunny"     :{"v4":["213.218.128.0/20","185.200.116.0/22"],"v6":["2a10:9340::/32"]},
    "KeyCDN"    :{"v4":["94.103.152.0/21","185.229.4.0/22"],"v6":["2a02:4780::/32"]},
    "CDN77"     :{"v4":["185.59.220.0/22","193.22.120.0/22"],"v6":["2a00:b700::/32"]},
    "Sucuri"    :{"v4":["192.124.249.0/24","185.93.228.0/22"],"v6":["2a02:fe80::/29"]},
    "StackPath" :{"v4":["151.139.0.0/16","198.57.240.0/21"],"v6":["2604:4480::/32"]},
}

IRAN_ISPS = {
    "MCI AS44244"       :["78.38.0.0/16","78.39.0.0/16","85.185.0.0/16","91.98.0.0/16"],
    "Irancell AS197207" :["46.225.0.0/16","46.224.0.0/16","188.136.0.0/16","188.137.0.0/16"],
    "Rightel AS57218"   :["37.32.0.0/16","37.33.0.0/16"],
    "Shatel AS31549"    :["82.99.192.0/18","94.182.0.0/16"],
    "Asiatech AS25184"  :["5.53.32.0/20","5.52.0.0/16"],
    "Pars AS16322"      :["78.157.32.0/20","78.155.0.0/16"],
    "Respina AS48159"   :["188.229.0.0/16","5.134.128.0/18"],
    "TCI AS48147"       :["194.225.0.0/16","195.146.32.0/21"],
    "Afranet"           :["217.144.80.0/20","82.102.16.0/20"],
    "Mobinnet AS50810"  :["5.160.0.0/16","5.161.0.0/16"],
    "Ziatel AS49100"    :["31.14.80.0/20","31.14.64.0/20"],
    "Neda AS12880"      :["31.40.0.0/16","31.41.0.0/16"],
    "Sabanet"           :["213.176.0.0/16","62.220.96.0/19"],
}

CF_SNIS = [
    "cloudflare.com","speed.cloudflare.com","one.one.one.one",
    "www.cloudflare.com","blog.cloudflare.com",
    "developers.cloudflare.com","dash.cloudflare.com",
]

COMMON_PORTS = {
    80:"HTTP",443:"HTTPS",8080:"HTTP-Alt",8443:"HTTPS-Alt",
    2052:"CF-Alt",2053:"CF-TLS",2082:"CF-Alt2",2083:"CF-TLS2",
    2086:"CF-Alt3",2087:"CF-TLS3",2095:"CF-Alt4",2096:"CF-TLS4",
    22:"SSH",21:"FTP",25:"SMTP",53:"DNS",110:"POP3",143:"IMAP",
    3306:"MySQL",5432:"PgSQL",6379:"Redis",27017:"MongoDB",
}

# ══════════════════════════════════════════════════════════════════
#  FAST IP GENERATOR — Pre-computed tuples, ~2ms per 1000 IPv4
# ══════════════════════════════════════════════════════════════════

def _precompute(cidrs):
    nets=[]; weights=[]
    for c in cidrs:
        try:
            net=ipaddress.ip_network(c,strict=False)
            size=net.num_addresses-2
            if size>0:
                nets.append((int(net.network_address),size,net.version))
                weights.append(size)
        except: pass
    return nets,weights

def _build_cum(weights):
    total=sum(weights); cum=[]; c=0.0
    for w in weights: c+=w/total; cum.append(c)
    return cum

def generate_ips_fast(count,cidrs):
    nets,weights=_precompute(cidrs)
    if not nets: return []
    cum=_build_cum(weights)
    result=set(); max_tries=count*5
    for _ in range(max_tries):
        if len(result)>=count: break
        r=random.random()
        idx=0
        for i,cv in enumerate(cum):
            if r<=cv: idx=i; break
        base,size,_=nets[idx]
        result.add(str(ipaddress.ip_address(base+random.randint(1,size))))
    return list(result)

def show_gen(count,cidrs,label=""):
    v4c=sum(1 for c in cidrs if ":"not in c)
    v6c=sum(1 for c in cidrs if ":"in c)
    vtag=f"v4:{v4c}" + (f" v6:{v6c}" if v6c else "")
    print(f"\n  {O}◆{RST} {W}Generating {count:,} IPs {DIM}[{label or 'RIX'} | {vtag}]{RST} ...",end="",flush=True)
    t0=time.perf_counter()
    ips=generate_ips_fast(count,cidrs)
    ms=(time.perf_counter()-t0)*1000
    print(f"\r  {G}◆ {W}{len(ips):,} IPs generated in {G}{ms:.0f}ms{RST} {DIM}[{label}]{RST}          ")
    return ips

# ══════════════════════════════════════════════════════════════════
#  O(1) CIDR CHECKER
# ══════════════════════════════════════════════════════════════════

class CidrSet:
    __slots__=("_r",)
    def __init__(self,cidrs):
        self._r=[]
        for c in cidrs:
            try:
                net=ipaddress.ip_network(c,strict=False)
                b=net.prefixlen; mb=128 if net.version==6 else 32
                mask=((1<<b)-1)<<(mb-b)&((1<<mb)-1)
                self._r.append((int(net.network_address)&mask,mask))
            except: pass
    def __contains__(self,ip):
        try:
            a=int(ipaddress.ip_address(ip))
            return any((a&m)==n for n,m in self._r)
        except: return False

_CF_V4=CidrSet(CF_CIDRS_V4)
_CF_V6=CidrSet(CF_CIDRS_V6)
def is_cf_ip(ip): return ip in _CF_V4 or ip in _CF_V6

# ══════════════════════════════════════════════════════════════════
#  BG CIDR UPDATER
# ══════════════════════════════════════════════════════════════════

_cidr_lock=threading.Lock()
_cidr_cache={"v4":list(CF_CIDRS_V4),"v6":list(CF_CIDRS_V6),"updated":None,"source":"built-in"}

def _fetch_cidrs():
    new={"v4":[],"v6":[]}
    for ver,url in [("v4","https://www.cloudflare.com/ips-v4"),("v6","https://www.cloudflare.com/ips-v6")]:
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"curl/7.88.0"})
            cs=[l.strip() for l in urllib.request.urlopen(req,timeout=10).read().decode().strip().splitlines() if "/" in l]
            if cs: new[ver]=cs
        except: pass
    return new

def _bg_loop():
    while True:
        try:
            f=_fetch_cidrs()
            with _cidr_lock:
                if f["v4"]: _cidr_cache["v4"]=f["v4"]
                if f["v6"]: _cidr_cache["v6"]=f["v6"]
                _cidr_cache["updated"]=datetime.now().strftime("%H:%M")
                _cidr_cache["source"]="live"
        except: pass
        time.sleep(6*3600)

def start_bg(): threading.Thread(target=_bg_loop,daemon=True).start()

def live_cidrs(ver):
    with _cidr_lock:
        v4=list(_cidr_cache["v4"]); v6=list(_cidr_cache["v6"])
    if ver==4: return v4
    elif ver==6: return v6
    return v4+v6

# ══════════════════════════════════════════════════════════════════
#  IPv6 SUPPORT
# ══════════════════════════════════════════════════════════════════

_ipv6_ok=None
def has_ipv6():
    global _ipv6_ok
    if _ipv6_ok is not None: return _ipv6_ok
    try:
        s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.settimeout(3)
        s.connect(("2606:4700:4700::1111",53,0,0)); s.close(); _ipv6_ok=True
    except:
        try: socket.socket(socket.AF_INET6,socket.SOCK_STREAM).close(); _ipv6_ok=False
        except: _ipv6_ok=False
    return _ipv6_ok

# ══════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════

lock=threading.Lock(); clean_ips=[]; scanned_count=0; LANG_KEY="en"
def T(k): return LANG[LANG_KEY].get(k,k)

def get_base():
    if getattr(sys,"frozen",False): return os.path.dirname(sys.executable)
    try: return os.path.dirname(os.path.abspath(__file__))
    except: return os.getcwd()

def get_dl():
    for p in ["/sdcard/Download","/storage/emulated/0/Download","/sdcard/Downloads","/storage/emulated/0/Downloads"]:
        if os.path.isdir(p): return p
    dl=os.path.join(os.path.expanduser("~"),"Downloads")
    return dl if os.path.isdir(dl) else os.path.expanduser("~")

BASE_DIR=get_base(); SAVE_DIR=get_dl()
IPS_FILE=os.path.join(SAVE_DIR,"RIX-CLEAN.txt")
HIST_FILE=os.path.join(BASE_DIR,"rix_history.json")

# ══════════════════════════════════════════════════════════════════
#  LANGUAGE
# ══════════════════════════════════════════════════════════════════

LANG={
"en":{
    "title"    :"RIX SCANNER v11.0 — Ultimate CDN Scanner",
    "subtitle" :"IPv4+IPv6 | Real TLS | CIDR-detect | NET-MELI | Multi-CDN",
    "m_start"  :"Start Scan          [full config]",
    "m_quick"  :"Quick Scan          [AI-preset, 2Q]",
    "m_netmeli":"NET-MELI            [Iran ISP optimized]",
    "m_multi"  :"Multi-CDN           [Fastly/Gcore/Bunny+]",
    "m_port"   :"Port Scanner        [real TCP]",
    "m_hist"   :"History             [last 10]",
    "m_export" :"Export              [TXT/JSON/CSV/v2ray]",
    "m_speed"  :"Speed Test          [real download]",
    "m_sched"  :"Auto Scheduler      [repeat scan]",
    "m_update" :"Update CIDRs        [Cloudflare API]",
    "m_lang"   :"Language            [EN/FA]",
    "m_exit"   :"Exit",
    "choose"   :"Choose",
    "checking" :"Checking connection ...",
    "vpn_warn" :"NON-IRANIAN IP — disable VPN for accuracy",
    "vpn_det"  :"VPN/PROXY DETECTED",
    "ok_ir"    :"[OK] Iranian IP confirmed — No VPN — Ready!",
    "ask_ver"  :"IP Version",
    "v4only"   :"1. IPv4 only",
    "v6only"   :"2. IPv6 only",
    "both"     :"3. IPv4 + IPv6 (both)",
    "v6warn"   :"[!] IPv6 unavailable on this system — using IPv4",
    "gen_mode" :"Generation Mode",
    "mode_cf"  :"Pure Cloudflare (standard)",
    "mode_mix" :"Iran-Optimized  (70% CF + 30% fast-edge)",
    "mode_fast":"Fast-Edge       (best subnets for Iran)",
    "count_q"  :"How many IPs? (no limit)",
    "lat_q"    :"Max latency (ms)?",
    "to_q"     :"Timeout per IP (s)?",
    "delay_q"  :"Delay (s)?",
    "sni_q"    :"SNI?",
    "ready_q"  :"Ready to scan?",
    "cancel"   :"Cancelled.",
    "done"     :"SCAN COMPLETE",
    "saved"    :"RIX-CLEAN.txt saved",
    "no_clean" :"No clean IPs found. Try higher latency or more IPs.",
    "top10"    :"TOP 10 FASTEST CLEAN IPs",
    "enter"    :"Press ENTER ...",
    "back"     :"Press ENTER to return to menu ...",
    "no_hist"  :"No history yet.",
    "scanned"  :"Scanned",
    "clean"    :"Clean",
    "prate"    :"pass rate",
    "fin"      :"Finished",
    "ips_s"    :"IPs/s",
    "isp_det"  :"ISP Detected",
    "your_isp" :"Your ISP",
},
"fa":{
    "title"    :"RIX SCANNER v11.0 — اسکنر CDN حرفه‌ای",
    "subtitle" :"IPv4+IPv6 | TLS واقعی | CIDR | نت‌ملی | چند CDN",
    "m_start"  :"اسکن کامل           [تنظیمات دستی]",
    "m_quick"  :"اسکن سریع           [هوش‌مصنوعی، ۲ سوال]",
    "m_netmeli":"نت ملی              [بهینه ISP ایران]",
    "m_multi"  :"چند CDN             [Fastly/Gcore/Bunny+]",
    "m_port"   :"پورت اسکنر          [TCP واقعی]",
    "m_hist"   :"تاریخچه             [آخرین ۱۰]",
    "m_export" :"خروجی               [TXT/JSON/CSV/v2ray]",
    "m_speed"  :"تست سرعت            [دانلود واقعی]",
    "m_sched"  :"زمان‌بندی            [اسکن تکراری]",
    "m_update" :"آپدیت CIDR          [API کلودفلر]",
    "m_lang"   :"زبان                [EN/FA]",
    "m_exit"   :"خروج",
    "choose"   :"انتخاب",
    "checking" :"بررسی اتصال ...",
    "vpn_warn" :"آی‌پی غیر ایرانی — VPN را خاموش کن",
    "vpn_det"  :"VPN/پروکسی شناسایی شد",
    "ok_ir"    :"[OK] آی‌پی ایرانی تایید شد — بدون VPN — آماده!",
    "ask_ver"  :"نسخه IP",
    "v4only"   :"1. فقط IPv4",
    "v6only"   :"2. فقط IPv6",
    "both"     :"3. هردو IPv4 + IPv6",
    "v6warn"   :"[!] IPv6 پشتیبانی نمی‌شود — از IPv4 استفاده می‌شود",
    "gen_mode" :"حالت تولید",
    "mode_cf"  :"خالص کلودفلر",
    "mode_mix" :"بهینه ایران (۷۰٪ CF + ۳۰٪ لبه سریع)",
    "mode_fast":"لبه‌های سریع (بهترین subnet برای ایران)",
    "count_q"  :"تعداد آی‌پی؟ (بدون محدودیت)",
    "lat_q"    :"حداکثر تاخیر (ms)?",
    "to_q"     :"مهلت هر آی‌پی (ثانیه)?",
    "delay_q"  :"تاخیر (ثانیه)?",
    "sni_q"    :"SNI?",
    "ready_q"  :"آماده اسکن؟",
    "cancel"   :"لغو شد.",
    "done"     :"اسکن کامل شد",
    "saved"    :"RIX-CLEAN.txt ذخیره شد",
    "no_clean" :"آی‌پی تمیز پیدا نشد. تاخیر یا تعداد را بالاتر ببر.",
    "top10"    :"برترین ۱۰ آی‌پی سریع",
    "enter"    :"ENTER را بزن ...",
    "back"     :"ENTER برای برگشت به منو ...",
    "no_hist"  :"تاریخچه‌ای وجود ندارد.",
    "scanned"  :"اسکن‌شده",
    "clean"    :"تمیز",
    "prate"    :"درصد موفق",
    "fin"      :"تمام شد",
    "ips_s"    :"آی‌پی/ثانیه",
    "isp_det"  :"ISP شناسایی‌شده",
    "your_isp" :"ISP شما",
}}

# ══════════════════════════════════════════════════════════════════
#  HISTORY
# ══════════════════════════════════════════════════════════════════
def hist_load():
    try:
        if os.path.exists(HIST_FILE):
            with open(HIST_FILE) as f: return json.load(f)
    except: pass
    return []

def hist_save(e):
    h=hist_load(); h.insert(0,e); h=h[:10]
    try:
        with open(HIST_FILE,"w") as f: json.dump(h,f,indent=2)
    except: pass

# ══════════════════════════════════════════════════════════════════
#  BANNER — RIX ASCII ART
# ══════════════════════════════════════════════════════════════════
def banner():
    os.system("cls" if os.name=="nt" else "clear")
    h=hist_load(); last=f"Last: {h[0]['date']} | {h[0]['clean']} clean" if h else "No scan history"
    with _cidr_lock:
        src=_cidr_cache.get("source","built-in"); upd=_cidr_cache.get("updated","—")
        nv4=len(_cidr_cache["v4"]); nv6=len(_cidr_cache["v6"])
    v6b=f"{G}IPv6✔{RST}" if has_ipv6() else f"{DIM}IPv4{RST}"
    cb=f"{G}[LIVE@{upd}]{RST}" if src=="live" else f"{O}[BUILT-IN]{RST}"

    print(f"""
{O}╔══════════════════════════════════════════════════════════════════════════╗{RST}
{O}║{RST}                                                                          {O}║{RST}
{O}║{W}{BLD}  ██████╗ ██╗██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗  {O}║{RST}
{O}║{W}{BLD}  ██╔══██╗██║╚██╗██╔╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║  {O}║{RST}
{O}║{W}{BLD}  ██████╔╝██║ ╚███╔╝     ███████╗██║     ███████║██╔██╗██║██╔██╗██║  {O}║{RST}
{O}║{W}{BLD}  ██╔══██╗██║ ██╔██╗     ╚════██║██║     ██╔══██║██║╚████║██║╚████║  {O}║{RST}
{O}║{W}{BLD}  ██║  ██║██║██╔╝╚██╗    ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║  {O}║{RST}
{O}║{W}{BLD}  ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝  {O}║{RST}
{O}║{RST}                                                                          {O}║{RST}
{O}╠══════════════════════════════════════════════════════════════════════════╣{RST}
{O}║{Y}{BLD}  ⚡  {T('title'):<67}{O}║{RST}
{O}║{DIM}  {T('subtitle'):<70}{O}║{RST}
{O}╠══════════════════════════════════════════════════════════════════════════╣{RST}
{O}║{DIM}  CIDRs v4={W}{nv4}{DIM} v6={W}{nv6}{DIM} {cb}  {v6b}  Save:{W}{os.path.basename(IPS_FILE)}{DIM}{' '*10}{O}║{RST}
{O}║{GR}  {last:<70}{O}║{RST}
{O}╚══════════════════════════════════════════════════════════════════════════╝{RST}
""")

# ══════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════
def main_menu():
    banner()
    opts=[
        (G,"1",T("m_start")),(Y,"2",T("m_quick")),
        (M,"3",T("m_netmeli")),(C,"4",T("m_multi")),
        (Y,"5",T("m_port")),(B,"6",T("m_hist")),
        (G,"7",T("m_export")),(Y,"8",T("m_speed")),
        (M,"9",T("m_sched")),(C,"A",T("m_update")),
        (B,"L",T("m_lang")),(R,"0",T("m_exit")),
    ]
    w=54
    print(f"  {O}╔{'═'*w}╗{RST}")
    title="MAIN MENU" if LANG_KEY=="en" else "منوی اصلی"
    print(f"  {O}║{Y}{BLD}  ◆ RIX SCANNER — {title:<35}{O}║{RST}")
    print(f"  {O}╠{'═'*w}╣{RST}")
    for col,num,lbl in opts:
        print(f"  {O}║{RST}  {col}{BLD}{num}{RST}  {W}{lbl:<50}{O}║{RST}")
    print(f"  {O}╚{'═'*w}╝{RST}")
    valid={o[1] for o in opts}
    while True:
        ch=input(f"\n  {Y}◆ {T('choose')} [0-9/A/L]: {RST}").strip().upper()
        if ch in valid: return ch
        print(f"  {R}Invalid.{RST}")

# ══════════════════════════════════════════════════════════════════
#  GEOIP + ISP
# ══════════════════════════════════════════════════════════════════
def geoip():
    for url in ["https://ipapi.co/json/","http://ip-api.com/json/"]:
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"curl/7.88.0"})
            d=json.loads(urllib.request.urlopen(req,timeout=6).read().decode())
            cc=(d.get("country_code") or d.get("countryCode") or "??").upper()
            return {"ip":d.get("ip") or d.get("query") or "?","cc":cc,
                    "country":d.get("country_name") or d.get("country") or "?",
                    "city":d.get("city") or "?",
                    "isp":d.get("org") or d.get("isp") or "?","asn":d.get("asn") or ""}
        except: continue
    return {"ip":"?","cc":"??","country":"?","city":"?","isp":"?","asn":""}

def detect_isp(isp,asn):
    il=isp.lower(); ac=asn.replace("AS","").split()[0] if asn else ""
    for kws,name,cidrs in [
        (["44244","hamrah","mci"],"MCI",IRAN_ISPS["MCI AS44244"]),
        (["197207","irancell","mtn"],"Irancell",IRAN_ISPS["Irancell AS197207"]),
        (["57218","rightel"],"Rightel",IRAN_ISPS["Rightel AS57218"]),
        (["31549","shatel"],"Shatel",IRAN_ISPS["Shatel AS31549"]),
        (["25184","asiatech"],"Asiatech",IRAN_ISPS["Asiatech AS25184"]),
        (["16322","pars"],"Pars",IRAN_ISPS["Pars AS16322"]),
        (["48159","respina"],"Respina",IRAN_ISPS["Respina AS48159"]),
        (["48147","tci"],"TCI",IRAN_ISPS["TCI AS48147"]),
        (["afranet","fanava"],"Afranet",IRAN_ISPS["Afranet"]),
        (["50810","mobinnet"],"Mobinnet",IRAN_ISPS["Mobinnet AS50810"]),
        (["49100","ziatel"],"Ziatel",IRAN_ISPS["Ziatel AS49100"]),
        (["12880","neda"],"Neda",IRAN_ISPS["Neda AS12880"]),
        (["sabanet","dd3"],"Sabanet",IRAN_ISPS["Sabanet"]),
    ]:
        for kw in kws:
            if kw in il or kw in ac: return name,cidrs
    return None,[]

# ══════════════════════════════════════════════════════════════════
#  VPN DETECTOR
# ══════════════════════════════════════════════════════════════════
def detect_vpn():
    print(f"\n  {Y}◆ {T('checking')}{RST}\n")
    info=geoip()
    ip,cc=info["ip"],info["cc"]; isp=info["isp"][:42]
    flag=f"{G}[IR]{RST}" if cc=="IR" else f"{R}[{cc}]{RST}"
    W_=50
    print(f"  {O}╔{'─'*W_}╗{RST}")
    print(f"  {O}║{Y}{BLD}  {flag}{Y}{BLD} Connection Info{' '*(W_-18)}{O}║{RST}")
    print(f"  {O}╠{'─'*W_}╣{RST}")
    for k,v in [("IP",ip),("Country",info["country"]),("City",info["city"]),("ISP",isp)]:
        print(f"  {O}║{RST}  {DIM}{k:<9}{RST}: {W}{v:<{W_-13}}{O}║{RST}")
    print(f"  {O}╚{'─'*W_}╝{RST}")

    issues=[]
    if os.name!="nt":
        try:
            ifaces=os.popen("ip link show 2>/dev/null").read().lower()
            for n in ["tun0","tun1","tap0","wg0","ppp0","nordlynx","proton0","utun0","utun1"]:
                if n in ifaces: issues.append(f"VPN iface: {n}")
        except: pass
    for v in ["http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]:
        if os.environ.get(v): issues.append(f"Proxy: {v}")
    try:
        req=urllib.request.Request("https://1.1.1.1/cdn-cgi/trace",headers={"Host":"one.one.one.one"})
        tr=urllib.request.urlopen(req,timeout=5).read().decode()
        if "warp=on" in tr or "warp=plus" in tr: issues.append("WARP is ON")
    except: pass

    not_iran=cc not in("IR","??"); problem=issues or not_iran

    if not_iran:
        print(f"\n  {R}╔{'═'*48}╗\n  ║  {T('vpn_warn'):<46}║\n  ╚{'═'*48}╝{RST}")
    if issues:
        print(f"\n  {R}╔{'═'*48}╗\n  ║  {T('vpn_det'):<46}║{RST}")
        for i in issues: print(f"  {R}║{RST}  {Y}▸ {i:<46}{R}║{RST}")
        print(f"  {R}╚{'═'*48}╝{RST}")

    if problem:
        if input(f"\n  {Y}Continue? (y/N): {RST}").strip().lower()!="y":
            print(f"\n  {R}Aborted.{RST}\n"); return None
    else:
        print(f"\n  {G}◆ {T('ok_ir')}{RST}\n")
    return info

# ══════════════════════════════════════════════════════════════════
#  IP VERSION SELECTOR
# ══════════════════════════════════════════════════════════════════
def ask_ipver():
    v6=has_ipv6()
    print(f"\n  {C}╔{'─'*42}╗{RST}")
    print(f"  {C}║{Y}{BLD}  ◆ {T('ask_ver'):<38}{C}║{RST}")
    print(f"  {C}╠{'─'*42}╣{RST}")
    print(f"  {C}║{RST}  {Y}1{RST}  {W}{T('v4only'):<38}{C}║{RST}")
    if v6:
        print(f"  {C}║{RST}  {Y}2{RST}  {G}{T('v6only'):<38}{C}║{RST}")
        print(f"  {C}║{RST}  {Y}3{RST}  {M}{T('both'):<38}{C}║{RST}")
    else:
        print(f"  {C}║{RST}  {R}2{RST}  {DIM}{T('v6only')} [N/A]{' '*8}{C}║{RST}")
        print(f"  {C}║{RST}  {R}3{RST}  {DIM}{T('both')} [IPv6 N/A]{' '*5}{C}║{RST}")
    print(f"  {C}╚{'─'*42}╝{RST}")
    while True:
        ch=input(f"\n  {Y}[1]: {RST}").strip()
        if not ch or ch=="1": return 4
        if ch=="2":
            if not v6: print(f"  {R}{T('v6warn')}{RST}"); return 4
            return 6
        if ch=="3":
            if not v6: print(f"  {Y}{T('v6warn')}{RST}"); return 4
            return 0
        print(f"  {R}1/2/3{RST}")

def build_cidrs(ver,mode):
    v4=live_cidrs(4); v6=live_cidrs(6)
    if mode=="fast": v4=CF_IRAN_FAST_V4; v6=CF_IRAN_FAST_V6
    if ver==4: return v4
    elif ver==6: return v6
    return v4+v6

# ══════════════════════════════════════════════════════════════════
#  SNI CHOOSER
# ══════════════════════════════════════════════════════════════════
def choose_sni(default="cloudflare.com"):
    print(f"\n  {C}╔{'─'*50}╗{RST}")
    print(f"  {C}║{Y}  ◆ {T('sni_q'):<46}{C}║{RST}")
    print(f"  {C}╠{'─'*50}╣{RST}")
    for i,s in enumerate(CF_SNIS,1):
        print(f"  {C}║{RST}  {Y}{i}{RST}. {W}{s:<46}{C}║{RST}")
    print(f"  {C}║{RST}  {Y}0{RST}. {DIM}Custom{' '*42}{C}║{RST}")
    print(f"  {C}╚{'─'*50}╝{RST}")
    raw=input(f"\n  [{C}1{RST}]: ").strip()
    if not raw: return default
    if raw.isdigit():
        i=int(raw)
        if 1<=i<=len(CF_SNIS): return CF_SNIS[i-1]
        if i==0:
            c=input("  Custom: ").strip(); return c if c else default
    if "." in raw: return raw
    return default

# ══════════════════════════════════════════════════════════════════
#  SSL CONTEXT
# ══════════════════════════════════════════════════════════════════
def _mk_ssl():
    ctx=ssl.create_default_context()
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.set_ciphers("ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:ECDH+AES256:HIGH:!aNULL:!MD5:!DSS")
    try: ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    except: pass
    return ctx
_SSL=_mk_ssl()

# ══════════════════════════════════════════════════════════════════
#  REAL TLS TEST — Zero fake, IPv4+IPv6
# ══════════════════════════════════════════════════════════════════
def test_ip(ip,sni,timeout,check_cidr=True):
    is_v6=":"in ip; fam=socket.AF_INET6 if is_v6 else socket.AF_INET
    for attempt in range(2):
        res={"ip":ip,"latency":None,"tcp_ms":None,"tls_ms":None,
             "status":"fail","cf":False,"http_code":"","ipv":"6" if is_v6 else "4"}
        raw=None; retry=False
        try:
            t0=time.perf_counter()
            raw=socket.socket(fam,socket.SOCK_STREAM)
            raw.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            raw.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
            raw.settimeout(timeout)
            raw.connect((ip,443,0,0) if is_v6 else (ip,443))
            res["tcp_ms"]=round((time.perf_counter()-t0)*1000,1)

            t1=time.perf_counter()
            tls=_SSL.wrap_socket(raw,server_hostname=sni)
            res["tls_ms"]=round((time.perf_counter()-t1)*1000,1)
            tls.settimeout(timeout)

            tls.sendall((
                f"HEAD / HTTP/1.1\r\nHost:{sni}\r\n"
                f"User-Agent:Mozilla/5.0\r\nAccept:*/*\r\nConnection:close\r\n\r\n"
            ).encode())

            resp=b""
            try:
                while True:
                    c=tls.recv(2048)
                    if not c: break
                    resp+=c
                    if b"\r\n\r\n" in resp or len(resp)>6144: break
            except: pass
            finally:
                try: tls.close()
                except: pass

            res["latency"]=round((time.perf_counter()-t0)*1000,1)
            if not resp: res["status"]="no_resp"; break

            txt=resp.decode(errors="ignore"); low=txt.lower()
            if txt.startswith("HTTP/"):
                p=txt.split()
                if len(p)>=2: res["http_code"]=p[1]

            got_http=resp[:4]==b"HTTP"
            cf_s=any(h in low for h in ["cf-ray","cf-cache-status","server: cloudflare","cf-request-id"])
            cf_w=any(h in low for h in ["nel:","report-to:","cf-bgj","expect-ct"])

            if check_cidr:
                in_c=is_cf_ip(ip)
                if(in_c and got_http)or(cf_s and got_http)or(cf_w and got_http and in_c):
                    res["cf"]=True; res["status"]="clean"
                elif got_http: res["status"]="http_ok"
                else:          res["status"]="tls_ok"
            else:
                res["status"]="clean" if got_http else "tls_ok"
            break

        except ssl.SSLError:           res["status"]="ssl_err"
        except socket.timeout:         res["status"]="timeout";    retry=True
        except ConnectionRefusedError: res["status"]="refused"
        except OSError:                res["status"]="unreachable"; retry=True
        except Exception:              res["status"]="error"
        finally:
            if raw:
                try: raw.close()
                except: pass
        if not retry or attempt>=1: break
        time.sleep(0.1)
    return res

# ══════════════════════════════════════════════════════════════════
#  LATENCY COLOR
# ══════════════════════════════════════════════════════════════════
def lc(lat):
    if lat is None: return DIM
    if lat<80:  return G
    if lat<150: return C
    if lat<250: return Y
    if lat<400: return M
    return R

def status_line(res,idx,total,max_ms):
    ip,lat,st=res["ip"],res["latency"],res["status"]
    code=res.get("http_code",""); v6t=f" {CY}v6{RST}" if res.get("ipv")=="6" else ""
    filled=int(28*idx/total); bar=f"{B}{'█'*filled}{DIM}{'░'*(28-filled)}{RST}"; pct=idx/total*100
    if st=="clean":
        over=lat and lat>max_ms; col=R if over else lc(lat)
        badge=f"{R}[>{max_ms}ms]{RST}" if over else f"{G}[SAVED]{RST}"
        t=f"{G}[CLEAN]{RST} {col}{lat:>5.0f}ms{RST} {badge}{v6t}"
    elif st=="http_ok": t=f"{Y}[HTTP{code:>4}]{RST} {DIM}{(lat or 0):>4.0f}ms{RST}{v6t}"
    elif st=="tls_ok":  t=f"{C}[TLS]   {RST}{DIM}{(lat or 0):>4.0f}ms{RST}"
    elif st=="no_resp": t=f"{R}[NO-RESP]  {RST}"
    elif st=="timeout": t=f"{R}[TIMEOUT]  {RST}"
    elif st=="ssl_err": t=f"{R}[SSL-ERR]  {RST}"
    elif st=="refused": t=f"{R}[REFUSED]  {RST}"
    else:               t=f"{R}[{st[:8].upper()}]{RST}"
    print(f"  [{bar}]{DIM}{pct:5.1f}%{RST}  {W}{ip:<42}{RST}  {t}")

# ══════════════════════════════════════════════════════════════════
#  SCANNER ENGINE
# ══════════════════════════════════════════════════════════════════
def run_scan(ip_list,sni,delay,max_ms,timeout,threads,label="",check_cidr=True):
    global scanned_count,clean_ips
    scanned_count,clean_ips=0,[]; total=len(ip_list); t0=time.perf_counter()

    v4c=sum(1 for ip in ip_list if ":" not in ip)
    v6c=total-v4c

    print(f"\n  {O}╔{'═'*64}╗{RST}")
    print(f"  {O}║{Y}{BLD}  ◆ {label or T('done'):<60}{O}║{RST}")
    print(f"  {O}╠{'═'*64}╣{RST}")
    for k,v in [("SNI",sni),(f"{T('scanned')}/Max",f"{total:,} IPs / {max_ms}ms"),
                ("Config",f"Timeout:{timeout}s  Threads:{threads}"),
                ("IPs",f"IPv4:{v4c:,}  IPv6:{v6c:,}  Detection:CIDR+TLS+HTTP")]:
        print(f"  {O}║{DIM}  {k:<10}: {W}{v:<50}{O}║{RST}")
    print(f"  {O}╚{'═'*64}╝{RST}\n")
    time.sleep(0.15)

    # Fast TCP pre-filter (3× threads)
    def tcp_ok(ip,to=min(timeout,1.5)):
        fam=socket.AF_INET6 if ":"in ip else socket.AF_INET
        try:
            s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(to)
            s.connect((ip,443,0,0) if ":"in ip else (ip,443)); s.close(); return True
        except: return False

    print(f"  {DIM}◆ TCP pre-filter ...{RST}")
    alive=[]
    with ThreadPoolExecutor(max_workers=min(500,threads*3)) as ex:
        futs={ex.submit(tcp_ok,ip):ip for ip in ip_list}
        for f in as_completed(futs):
            if f.result(): alive.append(futs[f])
    pct_a=len(alive)/total*100 if total else 0
    print(f"  {G}◆{RST} {W}{len(alive):,}{RST}/{total:,} alive ({pct_a:.0f}%)\n")
    if not alive: print(f"  {R}No IPs responded on port 443.{RST}"); return

    idx=0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs={ex.submit(test_ip,ip,sni,timeout,check_cidr):ip for ip in alive}
        for fut in as_completed(futs):
            idx+=1; res=fut.result()
            with lock:
                scanned_count+=1
                if res["status"]=="clean" and res["latency"] and res["latency"]<=max_ms:
                    clean_ips.append((res["ip"],res["latency"],sni,res.get("ipv","4")))
                status_line(res,idx,len(alive),max_ms)
                if idx%100==0 or idx==len(alive):
                    el=time.perf_counter()-t0; sp=idx/el if el else 1
                    eta=(len(alive)-idx)/sp if sp else 0; pc=len(clean_ips)/idx*100 if idx else 0
                    print(f"\n  {DIM}[{idx}/{len(alive)}] {T('clean')}:{G}{len(clean_ips)}{DIM}({pc:.1f}%) | {sp:.0f}{T('ips_s')} | ETA {eta:.0f}s{RST}\n")
            if delay>0: time.sleep(delay/max(1,threads))

    clean_ips.sort(key=lambda x:x[1])
    el=time.perf_counter()-t0; sp=total/el if el else 0
    pc=len(clean_ips)/scanned_count*100 if scanned_count else 0
    print(f"\n  {O}╔{'─'*54}╗{RST}")
    print(f"  {O}║{DIM} ◆ {T('fin')}: {W}{el:.1f}s{DIM} | {sp:.0f}{T('ips_s')} | {T('clean')}:{G}{len(clean_ips)}{DIM}({pc:.1f}%) {O}║{RST}")
    print(f"  {O}╚{'─'*54}╝{RST}")

# ══════════════════════════════════════════════════════════════════
#  SAVE + REPORT
# ══════════════════════════════════════════════════════════════════
def save_report(meta=None):
    v4c=sum(1 for _,_,_,v in clean_ips if v=="4")
    v6c=sum(1 for _,_,_,v in clean_ips if v=="6")
    if clean_ips:
        os.makedirs(SAVE_DIR,exist_ok=True)
        with open(IPS_FILE,"w",encoding="utf-8") as f:
            for ip,_,_,_ in clean_ips: f.write(f"{ip}\n")

    pct=len(clean_ips)/scanned_count*100 if scanned_count else 0
    print(f"\n  {O}╔{'═'*64}╗{RST}")
    print(f"  {O}║{Y}{BLD}  ◆ {T('done'):<60}{O}║{RST}")
    print(f"  {O}╠{'═'*64}╣{RST}")
    print(f"  {O}║{DIM}  {T('scanned'):<14}: {W}{scanned_count:,}{' '*(46-len(f'{scanned_count:,}'))}{O}║{RST}")
    print(f"  {O}║{DIM}  {T('clean'):<14}: {W}{len(clean_ips):,} ({pct:.1f}% {T('prate')}){' '*(34-len(f'{len(clean_ips):,}'))}{O}║{RST}")
    print(f"  {O}║{DIM}  IPv4 clean    : {G}{v4c}{DIM}   IPv6 clean: {CY}{v6c}{' '*(36-len(str(v4c))-len(str(v6c)))}{O}║{RST}")
    if clean_ips:
        print(f"  {O}║{G}{BLD}  ◆ {T('saved')}: {IPS_FILE[:56]:<56}{O}║{RST}")
    print(f"  {O}╚{'═'*64}╝{RST}")

    if clean_ips:
        print(f"\n  {Y}{BLD}  ◆{'═'*56}◆{RST}")
        print(f"  {Y}{BLD}  ◆  {T('top10'):^52}  ◆{RST}")
        print(f"  {Y}{BLD}  ◆{'═'*56}◆{RST}")
        print(f"  {O}┌────┬──────────────────────────────────────────┬──────────┐{RST}")
        print(f"  {O}│{W} #  {O}│{W} {'IP':<41}{O}│{W} {'Latency':>8} {O}│{RST}")
        print(f"  {O}├────┼──────────────────────────────────────────┼──────────┤{RST}")
        medals={1:f"{Y}★{RST}",2:f"{W}▲{RST}",3:f"{M}●{RST}"}
        for rank,(ip,lat,_,ver) in enumerate(clean_ips[:10],1):
            m=medals.get(rank," "); vtag=f" {CY}v6{RST}" if ver=="6" else ""
            print(f"  {O}│{RST}{m}{Y}{rank:2}{RST} {O}│{RST} {W}{ip:<41}{O}│{RST} {lc(lat)}{lat:>6.1f}ms{RST}{vtag} {O}│{RST}")
        print(f"  {O}└────┴──────────────────────────────────────────┴──────────┘{RST}")

    if meta and clean_ips:
        hist_save({"date":datetime.now().strftime("%Y-%m-%d %H:%M"),
            "scanned":scanned_count,"clean":len(clean_ips),"v4":v4c,"v6":v6c,
            "top_ip":clean_ips[0][0],"top_lat":clean_ips[0][1],
            "mode":meta.get("mode","?"),"sni":meta.get("sni","?")})

# ══════════════════════════════════════════════════════════════════
#  INPUT HELPERS
# ══════════════════════════════════════════════════════════════════
def ask_int(p,d,lo=0,hi=999_999_999):
    while True:
        try:
            v=input(f"  {Y}◆ {p} {DIM}[{d}]{RST}: ").strip()
            val=int(v) if v else d
            if lo<=val<=hi: return val
            print(f"  {R}Min {lo}.{RST}")
        except ValueError: print(f"  {R}Numbers only.{RST}")

def ask_float(p,d,lo=0.0):
    while True:
        try:
            v=input(f"  {Y}◆ {p} {DIM}[{d}]{RST}: ").strip()
            val=float(v) if v else d
            if val>=lo: return val
        except ValueError: print(f"  {R}Decimal required.{RST}")

# ══════════════════════════════════════════════════════════════════
#  FLOWS
# ══════════════════════════════════════════════════════════════════
QP={"mode":"mixed","sni":"speed.cloudflare.com","timeout":3.0,"delay":0.0,"tf":5}

def flow_quick():
    banner()
    print(f"""
  {M}╔══════════════════════════════════════════════════════╗{RST}
  {M}║{Y}{BLD}  ⚡ RIX QUICK SCAN — {T('m_quick'):<33}{M}║{RST}
  {M}╠══════════════════════════════════════════════════════╣{RST}
  {M}║{DIM}  Mode    : Iran-Optimized (mixed fast-edge)         {M}║{RST}
  {M}║{DIM}  SNI     : speed.cloudflare.com                     {M}║{RST}
  {M}║{DIM}  Timeout : 3.0s | Delay: 0s | Auto threads          {M}║{RST}
  {M}║{DIM}  Detect  : CIDR+TLS+HTTP — zero simulation          {M}║{RST}
  {M}║{Y}  Only 2 questions — everything else is AI-preset    {M}║{RST}
  {M}╚══════════════════════════════════════════════════════╝{RST}
""")
    info=detect_vpn()
    if info is None: return
    ver=ask_ipver()
    cnt=ask_int(T("count_q"),300,10)
    mxl=ask_int(T("lat_q"),200,1)
    cidrs=build_cidrs(ver,QP["mode"])
    thr=min(200,max(50,cnt//QP["tf"]))
    ips=show_gen(cnt,cidrs,f"Quick {QP['mode']}")
    run_scan(ips,QP["sni"],QP["delay"],mxl,QP["timeout"],thr,"RIX Quick Scan")
    save_report({"mode":QP["mode"],"sni":QP["sni"]})
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_standard():
    banner()
    info=detect_vpn()
    if info is None: return
    print(f"\n  {C}╔{'─'*52}╗{RST}")
    print(f"  {C}║{Y}{BLD}  ◆ {T('gen_mode'):<48}{C}║{RST}")
    print(f"  {C}╠{'─'*52}╣{RST}")
    for n,v in [("1",T("mode_cf")),("2",T("mode_mix")),("3",T("mode_fast"))]:
        print(f"  {C}║{RST}  {Y}{n}{RST}  {W}{v:<48}{C}║{RST}")
    print(f"  {C}╚{'─'*52}╝{RST}")
    mode={"1":"cf","2":"mixed","3":"fast"}.get(input(f"\n  {Y}[1]: {RST}").strip(),"cf")
    ver =ask_ipver()
    cnt =ask_int(T("count_q"),500)
    mxl =ask_int(T("lat_q"),300,1)
    to  =ask_float(T("to_q"),4.0,0.5)
    dl  =ask_float(T("delay_q"),0.0,0.0)
    sni =choose_sni()
    thr =min(200,max(50,cnt//5))
    cidrs=build_cidrs(ver,mode)
    ips=show_gen(cnt,cidrs,f"{mode} v{ver or '4+6'}")
    while True:
        ans=input(f"\n  {Y}◆ {T('ready_q')} {G}YES{RST}/{R}NO{RST} → ").strip().upper()
        if ans=="YES": break
        if ans=="NO": print(f"\n  {Y}{T('cancel')}{RST}\n"); return
    run_scan(ips,sni,dl,mxl,to,thr,"RIX Full Scan")
    save_report({"mode":mode,"sni":sni})
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_netmeli():
    banner()
    print(f"\n  {M}╔{'═'*52}╗{RST}")
    print(f"  {M}║{Y}{BLD}  🇮🇷  RIX NET-MELI — {T('m_netmeli'):<31}{M}║{RST}")
    print(f"  {M}╚{'═'*52}╝{RST}\n")
    info=detect_vpn()
    if info is None: return
    isp_name,isp_cidrs=detect_isp(info["isp"],info["asn"])
    print(f"\n  {C}╔{'─'*50}╗{RST}")
    print(f"  {C}║{Y}{BLD}  ◆ {T('isp_det'):<46}{C}║{RST}")
    print(f"  {C}╠{'─'*50}╣{RST}")
    if isp_name:
        print(f"  {C}║{RST}  {T('your_isp')}: {G}{isp_name:<38}{C}║{RST}")
        print(f"  {C}║{RST}  Mode     : {G}NET-MELI (CF fast-edge + ISP match){C}  ║{RST}")
    else:
        print(f"  {C}║{RST}  {T('your_isp')}: {Y}{info['isp'][:38]:<38}{C}║{RST}")
        print(f"  {C}║{RST}  Mode     : {Y}Fast-Edge Priority{' '*23}{C}║{RST}")
    print(f"  {C}╚{'─'*50}╝{RST}")
    print(f"\n  {C}Known ISPs ({len(IRAN_ISPS)}):{RST}")
    for name in IRAN_ISPS:
        m=f"{G}◆ YOURS{RST}" if isp_name and isp_name in name else f"{DIM}       {RST}"
        print(f"    {m} {DIM}{name}{RST}")
    ver=ask_ipver()
    cnt=ask_int(T("count_q"),800)
    mxl=ask_int(T("lat_q"),250,1)
    to =ask_float(T("to_q"),3.5,0.5)
    sni=choose_sni("speed.cloudflare.com")
    thr=min(200,max(60,cnt//4))
    v4=CF_IRAN_FAST_V4+(isp_cidrs or [])
    v6=CF_IRAN_FAST_V6
    cidrs={4:v4,6:v6,0:v4+v6}.get(ver,v4)
    ips=show_gen(cnt,cidrs,"NET-MELI")
    while True:
        ans=input(f"\n  {Y}◆ {T('ready_q')} {G}YES{RST}/{R}NO{RST} → ").strip().upper()
        if ans=="YES": break
        if ans=="NO": print(f"\n  {Y}{T('cancel')}{RST}\n"); return
    run_scan(ips,sni,0.0,mxl,to,thr,"RIX NET-MELI Scan")
    save_report({"mode":"netmeli","sni":sni})
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_multi():
    banner()
    print(f"\n  {C}╔{'═'*52}╗{RST}")
    print(f"  {C}║{Y}{BLD}  🌐  RIX Multi-CDN — {T('m_multi'):<30}{C}║{RST}")
    print(f"  {C}╚{'═'*52}╝{RST}\n")
    provs=list(MULTI_CIDRS.keys())
    print(f"  {C}╔{'─'*56}╗{RST}")
    print(f"  {C}║{RST}  {Y}0{RST}  {G}ALL providers{' '*41}{C}║{RST}")
    for i,name in enumerate(provs,1):
        nv4=len(MULTI_CIDRS[name]["v4"]); nv6=len(MULTI_CIDRS[name].get("v6",[]))
        print(f"  {C}║{RST}  {Y}{i}{RST}  {W}{name:<18}{DIM} v4:{nv4} CIDRs  v6:{nv6} CIDRs{' '*9}{C}║{RST}")
    print(f"  {C}╚{'─'*56}╝{RST}")
    ch=input(f"\n  {Y}[0]: {RST}").strip()
    if ch.isdigit() and 1<=int(ch)<=len(provs):
        name=provs[int(ch)-1]
        v4=MULTI_CIDRS[name]["v4"]; v6=MULTI_CIDRS[name].get("v6",[])
    else:
        v4=[c for v in MULTI_CIDRS.values() for c in v["v4"]]
        v6=[c for v in MULTI_CIDRS.values() for c in v.get("v6",[])]
    ver=ask_ipver()
    cidrs={4:v4,6:v6,0:v4+v6}.get(ver,v4)
    cnt=ask_int(T("count_q"),400); mxl=ask_int(T("lat_q"),300,1)
    to=ask_float(T("to_q"),4.0,0.5); sni=choose_sni("speed.cloudflare.com")
    thr=min(200,max(50,cnt//5))
    ips=show_gen(cnt,cidrs,"Multi-CDN")
    while True:
        ans=input(f"\n  {Y}◆ {T('ready_q')} {G}YES{RST}/{R}NO{RST} → ").strip().upper()
        if ans=="YES": break
        if ans=="NO": print(f"\n  {Y}{T('cancel')}{RST}\n"); return
    run_scan(ips,sni,0.0,mxl,to,thr,"RIX Multi-CDN Scan",check_cidr=False)
    save_report({"mode":"multi","sni":sni})
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_port():
    banner()
    print(f"\n  {Y}╔{'═'*54}╗{RST}")
    print(f"  {Y}║{W}{BLD}  🔌  RIX Port Scanner — {T('m_port'):<30}{Y}║{RST}")
    print(f"  {Y}╚{'═'*54}╝{RST}\n")
    target=input(f"  {Y}◆ Target IP/host [1.1.1.1]: {RST}").strip() or "1.1.1.1"
    try: socket.getaddrinfo(target,443)
    except: print(f"\n  {R}Cannot resolve: {target}{RST}"); input(f"\n  {DIM}{T('enter')}{RST}"); return
    print(f"  {C}│{RST} 1. CF ports (80,443,2052-2096)")
    print(f"  {C}│{RST} 2. Common ports ({len(COMMON_PORTS)})")
    print(f"  {C}│{RST} 3. Custom range")
    ch=input(f"\n  {Y}[1]: {RST}").strip()
    if ch=="3":
        lo=ask_int("Start port",1,1,65534); hi=ask_int("End port",1024,2,65535)
        ports=list(range(lo,hi+1))
    elif ch=="2": ports=list(COMMON_PORTS.keys())
    else: ports=[80,443,2052,2053,2082,2083,2086,2087,2095,2096]
    to=ask_float("Timeout (s)",1.0,0.1)
    is_v6=":" in target; fam=socket.AF_INET6 if is_v6 else socket.AF_INET
    print(f"\n  {C}Scanning {len(ports)} ports on {W}{target}{RST} ...\n")
    open_p=[]; t0=time.perf_counter()
    def sp(port):
        try:
            t=time.perf_counter(); s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(to)
            r=s.connect_ex((target,port,0,0) if is_v6 else (target,port)); s.close()
            return port,(r==0),round((time.perf_counter()-t)*1000,1)
        except: return port,False,None
    with ThreadPoolExecutor(max_workers=min(200,len(ports))) as ex:
        futs=[ex.submit(sp,p) for p in ports]; done=0
        for f in as_completed(futs):
            done+=1; port,is_open,lat=f.result()
            svc=COMMON_PORTS.get(port,f"port-{port}")
            if is_open:
                open_p.append((port,svc,lat))
                print(f"  {G}[OPEN]{RST}  {W}{target}:{port:<6}{RST}  {G}{svc}{RST}  {DIM}{lat}ms{RST}")
            print(f"\r  {DIM}Progress: {done}/{len(ports)} | Open: {len(open_p)}{RST}",end="",flush=True)
    el=time.perf_counter()-t0; print()
    print(f"\n  {O}╔{'═'*50}╗{RST}")
    print(f"  {O}║{Y}{BLD}  ◆ Port Scan — {target:<34}{O}║{RST}")
    print(f"  {O}╠{'═'*50}╣{RST}")
    print(f"  {O}║{DIM}  Scanned:{W}{len(ports)}{DIM}  Open:{G}{len(open_p)}{DIM}  Time:{W}{el:.1f}s{' '*15}{O}║{RST}")
    if open_p:
        print(f"  {O}╠{'─'*50}╣{RST}")
        for port,svc,lat in sorted(open_p):
            print(f"  {O}║{G}  {port:<8}{W}{svc:<18}{DIM}{lat}ms{' '*(10-len(str(lat)))}{O}║{RST}")
    print(f"  {O}╚{'═'*50}╝{RST}")
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_hist():
    banner()
    h=hist_load()
    print(f"\n  {C}╔{'═'*72}╗{RST}")
    print(f"  {C}║{Y}{BLD}  ◆ History ({len(h)} scans){' '*52}{C}║{RST}")
    print(f"  {C}╠{'─'*72}╣{RST}")
    if not h:
        print(f"  {C}║{DIM}  {T('no_hist'):<70}{C}║{RST}")
    else:
        print(f"  {C}║{W}  {'#':<3}{'Date':<18}{'Scanned':>9}{'Clean':>7}{'v4':>6}{'v6':>6}{'Best IP':<20}{'ms':>7} {C}║{RST}")
        print(f"  {C}╠{'─'*72}╣{RST}")
        for i,e in enumerate(h,1):
            lat=e.get("top_lat",0)
            print(f"  {C}║{Y}{i:3}{RST}  {W}{e['date']:<17}{RST}{e['scanned']:>9}{G}{e['clean']:>7}{RST}{e.get('v4','?'):>6}{CY}{e.get('v6','?'):>6}{RST}  {W}{e.get('top_ip','?'):<18}{RST} {lc(lat)}{lat:>5.0f}ms{RST} {C}║{RST}")
    print(f"  {C}╚{'═'*72}╝{RST}")
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_export():
    banner()
    if not clean_ips:
        print(f"\n  {R}◆ {T('no_clean')}{RST}"); input(f"\n  {DIM}{T('enter')}{RST}"); return
    print(f"\n  {C}╔{'─'*46}╗{RST}")
    print(f"  {C}║{Y}{BLD}  ◆ Export — {len(clean_ips)} clean IPs{' '*26}{C}║{RST}")
    print(f"  {C}╠{'─'*46}╣{RST}")
    for n,l in [("1","TXT  — plain IPs (RIX-CLEAN.txt)"),("2","JSON — with latency+SNI+version"),
                ("3","CSV  — spreadsheet format"),("4","v2ray — with comments"),("5","ALL  — all 4 formats")]:
        print(f"  {C}║{RST}  {Y}{n}{RST}. {W}{l:<42}{C}║{RST}")
    print(f"  {C}╚{'─'*46}╝{RST}")
    ch=input(f"\n  {Y}[1-5]: {RST}").strip()
    def do_txt():
        with open(IPS_FILE,"w") as f:
            for ip,_,_,_ in clean_ips: f.write(f"{ip}\n")
        return IPS_FILE
    def do_json():
        p=os.path.join(SAVE_DIR,"rix_export.json")
        with open(p,"w") as f:
            json.dump({"generated":datetime.now().isoformat(),"count":len(clean_ips),
                "ips":[{"ip":ip,"latency_ms":lat,"sni":sni,"ipv":ver} for ip,lat,sni,ver in clean_ips]},f,indent=2)
        return p
    def do_csv():
        p=os.path.join(SAVE_DIR,"rix_export.csv")
        with open(p,"w",newline="") as f:
            w=csv.writer(f); w.writerow(["ip","latency_ms","sni","ipv"])
            for ip,lat,sni,ver in clean_ips: w.writerow([ip,lat,sni,ver])
        return p
    def do_v2():
        p=os.path.join(SAVE_DIR,"rix_v2ray.txt")
        with open(p,"w") as f:
            f.write(f"# RIX Clean IPs — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            for ip,lat,sni,ver in clean_ips:
                f.write(f"{ip}  # {lat:.0f}ms  sni={sni}  IPv{ver}\n")
        return p
    for fn in {"1":[do_txt],"2":[do_json],"3":[do_csv],"4":[do_v2],
               "5":[do_txt,do_json,do_csv,do_v2]}.get(ch,[do_txt]):
        p=fn(); print(f"  {G}◆{RST} {p}")
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_speed():
    banner()
    if not clean_ips:
        print(f"\n  {R}◆ {T('no_clean')}{RST}"); input(f"\n  {DIM}{T('enter')}{RST}"); return
    top_n=min(10,len(clean_ips)); results=[]
    print(f"\n  {M}◆ Testing top {top_n} IPs — real 100KB download ...{RST}\n")
    for rank,(ip,lat,sni,ver) in enumerate(clean_ips[:top_n],1):
        fam=socket.AF_INET6 if ":"in ip else socket.AF_INET
        try:
            ctx=_mk_ssl(); t0=time.perf_counter()
            raw=socket.socket(fam,socket.SOCK_STREAM); raw.settimeout(8)
            raw.connect((ip,443,0,0) if ":"in ip else (ip,443))
            tls=ctx.wrap_socket(raw,server_hostname="speed.cloudflare.com"); tls.settimeout(8)
            tls.sendall(b"GET /__down?bytes=102400 HTTP/1.1\r\nHost:speed.cloudflare.com\r\nConnection:close\r\n\r\n")
            data=b""
            while len(data)<110000:
                c=tls.recv(8192)
                if not c: break
                data+=c
            el=time.perf_counter()-t0
            try: tls.close(); raw.close()
            except: pass
            bs=data.find(b"\r\n\r\n"); body=len(data)-(bs+4) if bs>0 else len(data)
            if el>0 and body>1000:
                spd=body/el/1024; results.append((ip,lat,spd,ver))
                bw=int(min(spd/500*32,32)); bar=f"{G}{'█'*bw}{'░'*(32-bw)}{RST}"
                sc=G if spd>200 else(Y if spd>50 else R)
                vtag=f" {CY}v6{RST}" if ver=="6" else ""
                print(f"  {W}{rank:2}. {ip:<42}{RST}  [{bar}]  {sc}{spd:>6.0f} KB/s{RST}  {DIM}{lat:.0f}ms{RST}{vtag}")
            else: print(f"  {W}{rank:2}. {ip:<42}{RST}  {R}too slow{RST}")
        except Exception as e: print(f"  {W}{rank:2}. {ip:<42}{RST}  {R}{str(e)[:30]}{RST}")
    if results:
        results.sort(key=lambda x:-x[2]); b=results[0]
        print(f"\n  {G}◆ Best: {W}{b[0]}{RST}  {G}{b[2]:.0f} KB/s{RST}  {DIM}{b[1]:.0f}ms{RST}")
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_sched():
    banner()
    print(f"\n  {Y}╔{'═'*48}╗{RST}")
    print(f"  {Y}║{W}{BLD}  ⏰  RIX Auto Scheduler{' '*25}{Y}║{RST}")
    print(f"  {Y}╚{'═'*48}╝{RST}\n")
    cnt=ask_int("IPs per scan",300,10)
    mxl=ask_int("Max latency (ms)",200,1)
    itv=ask_int("Interval (minutes)",30,1)
    rep=ask_int("Repeat count (0=infinite)",3,0)
    input(f"\n  {Y}ENTER to start (Ctrl+C to stop) ...{RST}")
    n=0
    try:
        while True:
            n+=1
            if rep>0 and n>rep: break
            print(f"\n  {M}╔─── RIX Auto #{n} @ {datetime.now().strftime('%H:%M:%S')} ───╗{RST}")
            cidrs=live_cidrs(4)
            ips=show_gen(cnt,cidrs,"scheduler")
            run_scan(ips,"speed.cloudflare.com",0.0,mxl,3.5,min(200,max(50,cnt//6)),"[SCHEDULER]")
            save_report({"mode":"scheduler","sni":"speed.cloudflare.com"})
            if rep>0 and n>=rep: break
            nxt=(datetime.now()+timedelta(minutes=itv)).strftime("%H:%M:%S")
            for rem in range(itv*60,0,-1):
                print(f"\r  {DIM}Next at {nxt} — {rem}s remaining   {RST}",end="",flush=True); time.sleep(1)
            print()
    except KeyboardInterrupt: print(f"\n\n  {Y}Scheduler stopped.{RST}")
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_update():
    global _CF_V4,_CF_V6
    banner()
    print(f"\n  {C}◆ Fetching latest CIDRs from Cloudflare ...{RST}\n")
    f=_fetch_cidrs()
    with _cidr_lock:
        if f["v4"]: _cidr_cache["v4"]=f["v4"]
        if f["v6"]: _cidr_cache["v6"]=f["v6"]
        _cidr_cache["updated"]=datetime.now().strftime("%H:%M"); _cidr_cache["source"]="live"
        _CF_V4=CidrSet(_cidr_cache["v4"]); _CF_V6=CidrSet(_cidr_cache["v6"])
    print(f"  {G}◆{RST} v4: {W}{len(_cidr_cache['v4'])}{RST} CIDRs   v6: {W}{len(_cidr_cache['v6'])}{RST} CIDRs")
    input(f"\n  {DIM}{T('back')}{RST}")

def flow_lang():
    global LANG_KEY; banner()
    print(f"\n  {M}╔{'═'*30}╗{RST}")
    print(f"  {M}║  ◆ Language / زبان         ║{RST}")
    print(f"  {M}╠{'═'*30}╣{RST}")
    print(f"  {M}║{RST}  {Y}1{RST}. 🇬🇧 English              {M}║{RST}")
    print(f"  {M}║{RST}  {Y}2{RST}. 🇮🇷 فارسی                {M}║{RST}")
    print(f"  {M}╚{'═'*30}╝{RST}")
    LANG_KEY="fa" if input(f"\n  [1/2]: ").strip()=="2" else "en"
    print(f"\n  {G}◆ {'زبان فارسی انتخاب شد.' if LANG_KEY=='fa' else 'English selected.'}{RST}\n"); time.sleep(0.6)

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    start_bg()
    threading.Thread(target=has_ipv6,daemon=True).start()
    while True:
        ch=main_menu()
        if   ch=="1": flow_standard()
        elif ch=="2": flow_quick()
        elif ch=="3": flow_netmeli()
        elif ch=="4": flow_multi()
        elif ch=="5": flow_port()
        elif ch=="6": flow_hist()
        elif ch=="7": flow_export()
        elif ch=="8": flow_speed()
        elif ch=="9": flow_sched()
        elif ch=="A": flow_update()
        elif ch=="L": flow_lang()
        elif ch=="0":
            banner(); print(f"\n  {O}◆ Bye! / خداحافظ!{RST}\n"); sys.exit(0)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt:
        print(f"\n\n{R}  ◆ Interrupted. Saving ...{RST}")
        if clean_ips: save_report()
        sys.exit(0)
