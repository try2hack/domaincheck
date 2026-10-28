#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domaincheck — ตรวจโดเมนว่าถูก ISP ไทยบล็อกหรือไม่ พร้อมสถานะทะเบียน

ใช้ dnspython ตัวเดียว ไม่ต้องลงอะไรเพิ่ม

    ./domaincheck.py x.com
    ./domaincheck.py x.com www.x.com --summary
    ./domaincheck.py x.com --http --json out.json
    ./domaincheck.py --file list.txt      (ไฟล์บรรทัดละโดเมน เช่น x.com)

สิ่งที่ตรวจให้
  * สถานะทะเบียน (RDAP) — จดหรือยัง, วันหมดอายุ, registrar, nameserver
  * คำตอบ DNS จาก resolver ของค่ายเน็ตบ้านไทย แยกตามค่าย
  * ถูกบล็อก / NXDOMAIN / ตอบต่างจากค่าอ้างอิง
  * (ตัวเลือก --http) เปิดเว็บจริงได้ไหม รหัสตอบกลับเท่าไร

รหัสออก 0 = ไม่พบการบล็อก, 1 = พบ, 2 = ใช้ผิดวิธี

ข้อจำกัด: เห็นแค่ชั้น DNS ถ้าค่ายบล็อกที่ชั้น HTTP/SNI จะดูปกติจากตรงนี้
"""
import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# import dnspython แบบ lazy — ให้ --help ใช้ได้แม้ยังไม่ได้ติดตั้ง
dns = None


def ensure_dns():
    """โหลด dnspython ครั้งแรกที่ต้องใช้จริง ถ้าไม่มีให้บอกวิธีติดตั้ง"""
    global dns
    if dns is None:
        try:
            import dns.exception
            import dns.resolver
        except ImportError:
            sys.exit("ต้องติดตั้ง dnspython ก่อน:  pip install dnspython")
        dns = sys.modules["dns"]
    return dns

# --------------------------------------------------------------------------
# resolver ของค่ายเน็ตบ้านไทย — คัดจาก 102 ตัว เหลือตัวที่ตอบจริงและจับบล็อกได้
# เก็บตัวที่เคยคืนหน้าบล็อกไว้ก่อน แล้วเติมตัวเร็วสุดของค่ายนั้น
# --------------------------------------------------------------------------
RESOLVERS = [
    ("AIS / AIS Fibre",      "110.164.252.222"),
    ("AIS / AIS Fibre",      "110.164.252.223"),
    ("AIS / AIS Fibre",      "110.164.193.206"),
    ("True Online",          "171.103.141.86"),
    ("True Online",          "61.91.5.74"),
    ("True Online",          "171.99.134.98"),
    ("3BB (JasTel)",         "58.82.152.44"),
    ("3BB (JasTel)",         "58.82.148.227"),
    ("3BB (JasTel)",         "203.130.152.97"),
    ("NT (CAT+TOT)",         "159.192.142.29"),
    ("NT (CAT+TOT)",         "110.77.138.250"),
    ("NT (CAT+TOT)",         "122.155.213.6"),
    ("Symphony",             "146.88.38.231"),
    ("Symphony",             "161.82.184.70"),
    ("Symphony",             "83.118.39.242"),
    ("Internet Thailand",    "203.150.199.17"),
    ("Internet Thailand",    "203.154.177.8"),
    ("Internet Thailand",    "203.154.91.1"),
    ("KSC",                  "203.209.87.99"),
    ("CS Loxinfo",           "203.146.237.237"),
    ("CS Loxinfo",           "27.254.58.88"),
    ("United Info Highway",  "115.31.133.178"),
    ("United Info Highway",  "43.249.65.207"),
]
BASELINE = "8.8.8.8"

# IP ที่ถูกคืนมาแทนโดเมนที่ถูกบล็อก
#   125.26.170.3   หน้าบล็อกของ TOT/NT
#   212.92.105.x   ตัวเปลี่ยนเส้นทางหน้าบล็อก (ตอบ 302 Redirecting)
#   185.150.189.29 ปลายทางที่ถูกสลับให้เมื่อบล็อก
#   192.168.x/10.x ปลายทางหลอกที่ทำให้เชื่อมต่อตาย
BLOCK_IPS = {"125.26.170.3", "185.150.189.29",
             "192.168.1.0", "192.168.1.1", "127.0.0.1", "0.0.0.0", "10.0.0.1"}
BLOCK_PREFIXES = ("212.92.105.",)


def is_block_ip(ip):
    return ip in BLOCK_IPS or ip.startswith(BLOCK_PREFIXES)

VERDICT_TH = {
    "blocked": "ถูกบล็อก",
    "nxdomain": "NXDOMAIN",
    "differs": "ตอบต่าง",
    "clean": "ปกติ",
    "timeout": "ไม่ตอบ",
    "error": "ผิดพลาด",
}

UA = "Mozilla/5.0 (compatible; domaincheck/1.0)"

# TLD ที่ rdap.org ไม่มีใน IANA bootstrap — ถามทะเบียนตรง
RDAP_FALLBACK = {
    "me": "https://rdap.identitydigital.services/rdap/",
    "io": "https://rdap.identitydigital.services/rdap/",
    "ac": "https://rdap.identitydigital.services/rdap/",
    "sh": "https://rdap.identitydigital.services/rdap/",
    "co": "https://rdap.registry.co/co/",
}

# suffix ระดับสองของไทย — โดเมนหลักจะมี 3 label เช่น example.co.th
THAI_2LD = {"co.th", "in.th", "ac.th", "go.th", "or.th", "net.th", "mi.th"}


def registrable_domain(domain):
    """ตัด subdomain ออกให้เหลือโดเมนที่จดทะเบียน (แบบง่าย ไม่ใช้ Public Suffix List)
    www.x.com -> x.com, www.google.co.th -> google.co.th"""
    labels = domain.split(".")
    keep = 3 if ".".join(labels[-2:]) in THAI_2LD else 2
    return ".".join(labels[-keep:]) if len(labels) > keep else domain


# --------------------------------------------------------------------------
def load_resolvers(path):
    """อ่าน resolver จากไฟล์บรรทัดละตัว: IP [ชื่อค่าย]  (# ขึ้นต้น = ข้าม)"""
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                continue
            out.append((parts[1].strip() if len(parts) > 1 else "ไม่ระบุ", parts[0]))
    return out


def resolve(server, name, timeout):
    """คืน (สถานะ, [IP]) — สถานะ: NOERROR / NXDOMAIN / TIMEOUT / ชื่อ exception"""
    ensure_dns()
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout + 3
    for _ in range(2):
        try:
            ans = r.resolve(name, "A", raise_on_no_answer=False, lifetime=timeout + 3)
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN", []
        except dns.resolver.NoNameservers:
            return "SERVFAIL", []
        except dns.exception.Timeout:
            continue
        except Exception as exc:                      # noqa: BLE001
            return type(exc).__name__, []
        if ans.rrset is None:
            return "NOANSWER", []
        return "NOERROR", sorted({x.address for x in ans.rrset})
    return "TIMEOUT", []


def _rdap_query(domain, timeout):
    """ถาม RDAP หนึ่งครั้ง — คืน (ชนิด, ข้อมูล): ("ok", json) / ("notfound", None) / ("error", ข้อความ)"""
    tld = domain.rsplit(".", 1)[-1]
    if tld in RDAP_FALLBACK:
        url = RDAP_FALLBACK[tld] + "domain/" + domain
    else:
        url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return "ok", json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # 404 ของ rdap.org เอง = ไม่มีบริการ RDAP สำหรับ TLD นี้ ไม่ใช่ "ยังไม่จด"
            # 404 ของทะเบียนจริงจะมาหลัง redirect (โฮสต์ปลายทางไม่ใช่ rdap.org)
            if urllib.parse.urlsplit(e.geturl() or url).hostname == "rdap.org":
                return "error", f"ไม่มีบริการ RDAP สำหรับ .{tld}"
            return "notfound", None
        return "error", f"HTTP {e.code}"
    except Exception as exc:                          # noqa: BLE001
        return "error", type(exc).__name__


def rdap_info(domain, timeout=25):
    """ข้อมูลทะเบียนจาก RDAP — คืน dict, หรือ None ถ้าไม่ได้จด
    dict ที่มี "error" = ตรวจไม่ได้ (เช่น TLD ไม่มีบริการ RDAP)
    ถ้าเป็น subdomain และได้ 404 จะลองถามโดเมนหลักแทน แล้วใส่ "queried" ไว้"""
    kind, d = _rdap_query(domain, timeout)
    queried = domain
    if kind == "notfound":
        parent = registrable_domain(domain)
        if parent != domain:
            queried = parent
            kind, d = _rdap_query(parent, timeout)
    if kind == "notfound":
        return None
    if kind == "error":
        return {"error": d}

    info = {"status": d.get("status", []), "ns": sorted(
        n.get("ldhName", "").lower() for n in d.get("nameservers", []) if n.get("ldhName"))}
    if queried != domain:
        info["queried"] = queried
    for ev in d.get("events", []):
        act = ev.get("eventAction", "")
        if act in ("expiration", "registration", "last changed"):
            info[act.replace(" ", "_")] = (ev.get("eventDate") or "")[:10]
    for ent in d.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            v = ent.get("vcardArray")
            if v and len(v) > 1:
                for item in v[1]:
                    if item[0] == "fn":
                        info["registrar"] = item[3]
    return info


def http_probe(domain, timeout=12):
    """เปิด https://domain — คืนข้อความสรุปสถานะ"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    last = "error"
    for scheme in ("https", "http"):
        req = urllib.request.Request(f"{scheme}://{domain}/", headers={"User-Agent": UA},
                                     method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return f"{r.status} {r.reason} ({scheme})"
        except urllib.error.HTTPError as e:
            return f"{e.code} {e.reason} ({scheme})"
        except socket.timeout:
            return "timeout"
        except Exception as exc:                      # noqa: BLE001
            last = type(exc).__name__
    return last


def judge(status, ips, base_status, base_ips):
    """ตัดสินผลของ resolver หนึ่งตัวเทียบกับค่าอ้างอิง (8.8.8.8)

    * IP ตรงกับค่าอ้างอิงทุกตัว                  -> clean (แม้เป็น 127.0.0.1 จริงๆ)
    * มี IP หน้าบล็อก                         -> blocked
    * ISP ไม่ตอบ                              -> timeout
    * ISP NXDOMAIN: อ้างอิง NOERROR            -> nxdomain (ซ่อนโดเมน)
                    อ้างอิง NXDOMAIN ด้วย     -> clean (ตรงกัน โดเมนไม่มีจริง)
    * ISP ตอบ IP:   อ้างอิง NOERROR            -> clean ถ้า IP ตรง ไม่งั้น differs
                    อ้างอิง NXDOMAIN/NOANSWER -> differs (ISP ตอบ IP ทั้งที่อ้างอิงไม่มี)
    * ISP NOANSWER ตรงกับอ้างอิง               -> clean
    * อ้างอิงล้มเหลว (TIMEOUT/SERVFAIL/...)      -> error เพราะเทียบไม่ได้
      ไม่ฟันธงว่าปกติ ทั้งที่ไม่มีอะไรให้เทียบ
    """
    if ips and base_status == "NOERROR" and set(ips) == set(base_ips):
        return "clean"
    if ips and any(is_block_ip(x) for x in ips):
        return "blocked"
    if status == "TIMEOUT":
        return "timeout"
    if status == "NXDOMAIN":
        if base_status == "NOERROR":
            return "nxdomain"
        if base_status == "NXDOMAIN":
            return "clean"
        return "error"
    if status in ("NOERROR", "NOANSWER"):
        if base_status == "NOERROR":
            return "clean" if set(ips) == set(base_ips) else "differs"
        if base_status in ("NXDOMAIN", "NOANSWER"):
            return "clean" if status == base_status == "NOANSWER" else "differs"
        return "error"
    return "error"


def check_domain(domain, resolvers, timeout, jobs, do_http, do_rdap=True):
    t0 = time.time()
    base_status, base_ips = resolve(BASELINE, domain, timeout)
    rows = []

    def one(item):
        brand, ip = item
        status, ips = resolve(ip, domain, timeout)
        verdict = judge(status, ips, base_status, base_ips)
        return {"brand": brand, "resolver": ip, "verdict": verdict,
                "status": status, "ips": ips}

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        rows = list(ex.map(one, resolvers))

    by_brand = {}
    for r in rows:
        b = by_brand.setdefault(r["brand"], {"total": 0, "blocked": 0, "nxdomain": 0,
                                             "differs": 0, "clean": 0, "timeout": 0,
                                             "error": 0})
        b["total"] += 1
        b[r["verdict"]] = b.get(r["verdict"], 0) + 1

    return {
        "domain": domain,
        "baseline": {"resolver": BASELINE, "status": base_status, "ips": base_ips},
        "rdap": rdap_info(domain) if do_rdap else None,
        "rdap_skipped": not do_rdap,
        "http": http_probe(domain) if do_http else None,
        "brands": by_brand,
        "rows": rows,
        "blocked_total": sum(1 for r in rows if r["verdict"] == "blocked"),
        "seconds": round(time.time() - t0, 1),
    }


# --------------------------------------------------------------------------
def render(results, summary_only=False):
    for res in results:
        d = res["domain"]
        base = res["baseline"]
        print(f"\n{'=' * 68}\n{d}\n{'=' * 68}")
        print(f"  อ้างอิง (8.8.8.8) : {base['status']} "
              f"{','.join(base['ips']) if base['ips'] else '-'}")
        rd = res["rdap"]
        if res.get("rdap_skipped"):
            print("  ทะเบียน           : ข้าม (--no-rdap)")
        elif rd is None:
            print("  ทะเบียน           : ยังไม่จดทะเบียน")
        elif "error" in rd:
            print(f"  ทะเบียน           : ตรวจไม่ได้ ({rd['error']})")
        else:
            of = f" (ทะเบียนของ {rd['queried']})" if rd.get("queried") else ""
            print(f"  ทะเบียน           : จดแล้ว{of} · หมดอายุ {rd.get('expiration', '?')}"
                  f" · {rd.get('registrar', '?')}")
            if rd.get("ns"):
                print(f"  nameserver        : {', '.join(rd['ns'])}")
        if res["http"]:
            print(f"  HTTP              : {res['http']}")

        if not summary_only:
            print(f"\n  {'ค่าย':<22}{'resolver':<17}{'ผล':<10}IP")
            print(f"  {'-' * 64}")
            for r in res["rows"]:
                mark = {"blocked": "!!", "nxdomain": "! ", "differs": "~ "}.get(r["verdict"], "  ")
                print(f"  {mark}{r['brand']:<20}{r['resolver']:<17}"
                      f"{VERDICT_TH[r['verdict']]:<10}{','.join(r['ips'])}")

        print(f"\n  สรุปตามค่าย")
        for brand, b in res["brands"].items():
            if b["blocked"]:
                tag = f"ถูกบล็อก {b['blocked']}/{b['total']}"
            elif b["nxdomain"]:
                tag = f"NXDOMAIN {b['nxdomain']}/{b['total']}"
            elif b["differs"]:
                tag = f"ตอบต่าง {b['differs']}/{b['total']}"
            elif b["timeout"]:
                tag = f"ไม่ตอบ {b['timeout']}/{b['total']}"
            elif b.get("error"):
                tag = f"ผิดพลาด {b['error']}/{b['total']}"
            elif b["clean"] < b["total"]:
                tag = f"ปกติ {b['clean']}/{b['total']}"
            else:
                tag = f"ปกติ {b['total']}/{b['total']}"
            print(f"    {brand:<24}{tag}")
        print(f"  รวม {res['blocked_total']} resolver คืนหน้าบล็อก · ใช้เวลา {res['seconds']}s")

    if len(results) > 1:
        brands = []
        for res in results:
            for b in res["brands"]:
                if b not in brands:
                    brands.append(b)
        print(f"\n{'=' * 68}\nตารางรวม\n{'=' * 68}")
        w = max(14, *(len(r["domain"]) for r in results)) + 2
        print(f"  {'ค่าย':<22}" + "".join(f"{r['domain']:<{w}}" for r in results))
        print(f"  {'-' * (22 + w * len(results))}")
        for b in brands:
            cells = []
            for res in results:
                x = res["brands"].get(b)
                if not x:
                    cells.append("-")
                elif x["blocked"]:
                    cells.append(f"บล็อก {x['blocked']}/{x['total']}")
                elif x["nxdomain"]:
                    cells.append(f"NX {x['nxdomain']}/{x['total']}")
                elif x["differs"]:
                    cells.append(f"ต่าง {x['differs']}/{x['total']}")
                elif x["timeout"]:
                    cells.append(f"ไม่ตอบ {x['timeout']}/{x['total']}")
                elif x.get("error"):
                    cells.append(f"ผิดพลาด {x['error']}/{x['total']}")
                else:
                    cells.append(f"ปกติ {x['total']}/{x['total']}")
            print(f"  {b:<22}" + "".join(f"{c:<{w}}" for c in cells))


def main():
    ap = argparse.ArgumentParser(
        description="ตรวจโดเมนว่าถูก ISP ไทยบล็อกหรือไม่ (และสถานะทะเบียน)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="ตัวอย่าง:\n"
               "  domaincheck.py x.com\n"
               "  domaincheck.py x.com www.x.com --summary\n"
               "  domaincheck.py x.com --http --json out.json\n"
               "  domaincheck.py --file list.txt   (บรรทัดละโดเมน เช่น x.com)")
    ap.add_argument("domains", nargs="*", help="โดเมนที่ต้องการตรวจ")
    ap.add_argument("-f", "--file", help="ไฟล์รายชื่อโดเมน บรรทัดละโดเมน")
    ap.add_argument("-r", "--resolver-file",
                    help="ไฟล์ resolver เอง (บรรทัดละตัว: IP [ชื่อค่าย])")
    ap.add_argument("-j", "--jobs", type=int, default=6,
                    help="จำนวนคำขอพร้อมกัน (ค่าเริ่มต้น 6 — สูงเกินจะทำให้ resolver ไทยทิ้งคำขอ)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="หมดเวลาแต่ละคำขอ (วินาที)")
    ap.add_argument("--http", action="store_true", help="เปิดเว็บจริงด้วย ตรวจรหัสตอบกลับ")
    ap.add_argument("--summary", action="store_true", help="แสดงแค่สรุป ไม่แยกราย resolver")
    ap.add_argument("--json", metavar="PATH", help="บันทึกผลทั้งหมดเป็น JSON")
    ap.add_argument("--no-rdap", action="store_true", help="ข้ามการตรวจทะเบียน")
    args = ap.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            domains += [ln.split("#")[0].strip() for ln in fh]
    # เอาซ้ำออกแบบไม่สนตัวพิมพ์ คงลำดับเดิม (X.com กับ x.com ตรวจครั้งเดียว)
    domains = list(dict.fromkeys(d.strip().lower().rstrip(".") for d in domains if d.strip()))
    # TODO(L3): โดเมนภาษาไทย/IDN ยังไม่รองรับ — ต้องแปลงเป็น punycode ด้วย IDNA2008
    #   (pip install idna; idna.encode(d, uts46=True, transitional=False)) ไม่ใช้ codec "idna"
    #   ของ Python เพราะเป็น IDNA2003 (faß.de -> fass.de) ตอนนี้ใส่ xn--... มาตรงๆ ได้
    if not domains:
        ap.error("ต้องระบุโดเมนอย่างน้อยหนึ่งโดเมน (หรือใช้ --file)")

    # แต่ละ label: ตัวอักษร/ตัวเลข/ขีด ไม่ขึ้นต้นหรือลงท้ายด้วยขีด ยาวไม่เกิน 63
    # ห้ามจุดนำหน้า/ต่อท้าย/จุดติดกัน, TLD เป็นตัวอักษร ≥2 หรือ punycode xn--
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    dom_re = rf"(?:{label}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})"
    bad = [d for d in domains if len(d) > 253 or not re.fullmatch(dom_re, d)]
    if bad:
        ap.error(f"รูปแบบโดเมนไม่ถูกต้อง: {', '.join(bad)}")

    resolvers = load_resolvers(args.resolver_file) if args.resolver_file else RESOLVERS
    if not resolvers:
        ap.error("ไม่พบ resolver ในไฟล์ที่ให้มา")

    ensure_dns()   # เช็กหลัง parse args เพื่อให้ --help ไม่ต้องใช้ dnspython
    print(f"ตรวจ {len(domains)} โดเมน ผ่าน {len(resolvers)} resolver "
          f"จาก {len({b for b, _ in resolvers})} ค่าย")

    results = []
    for d in domains:
        results.append(check_domain(d, resolvers, args.timeout, args.jobs, args.http,
                                    do_rdap=not args.no_rdap))

    render(results, summary_only=args.summary)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=1)
        print(f"\nบันทึกแล้ว: {args.json}")

    blocked = sum(1 for r in results if r["blocked_total"])
    print(f"\nสรุป: {blocked}/{len(results)} โดเมนถูกบล็อกอย่างน้อยหนึ่งค่าย")
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
