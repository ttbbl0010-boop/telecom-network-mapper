#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
telecom_network_mapper.py
==========================================================================
سكربت واحد يجمع الاكتشاف (شركات الاتصالات وكتل عناوينها) والتصنيف (بنية
تحتية / مشتركين) ويكتب النتائج بصيغة JSON منظّمة هرميًا.

⚡ هذا الإصدار مُعاد هيكلته للسرعة (كان التقدير السابق أيامًا/أسابيع):
  1) تُعالَج عدة دول بالتوازي (COUNTRY_WORKERS) بدل دولة واحدة في كل مرة.
  2) طلبات RIPEstat الفعلية مُقيَّدة بـ Semaphore عالمي (RIPESTAT_MAX_CONCURRENT
     = 8، حسب توصية RIPEstat) بغض النظر عن عدد الخيوط الكلي، فيمكن رفع عدد
     الخيوط بأمان دون تجاوز حد RIPEstat الفعلي.
  3) فحوصات PTR (DNS) لا تمر عبر RIPEstat إطلاقًا، فلها مجمّع خيوط خاص أوسع
     (DNS_MAX_CONCURRENT = 40) ومُشترك بين كل الدول/الكتل في وقت واحد،
     وعيّنات PTR الخمس لكل كتلة تُفحَص بالتوازي (لا بالتسلسل كما سابقًا).
  4) RDNS_MODE افتراضيًا "only_if_unclear": لا يُشغَّل فحص PTR (الأبطأ) إلا
     إن كان نص تسجيل RIR غير حاسم أصلًا - يقلّل عدد استعلامات DNS بشدة.
     غيّره إلى "always" إن أردت تأكيدًا مزدوجًا على كل كتلة (أبطأ لكن أدق قليلًا)،
     أو "never" لتعطيل PTR كليًا (الأسرع، يعتمد على RIR فقط).

  النتيجة المتوقعة: من "أيام/أسابيع" إلى غالبًا ساعات معدودة لتشغيل عالمي
  كامل، حسب استجابة الشبكة لديك - لا يمكن ضمان رقم دقيق من هنا.

🖥️  لتشغيله بدون إبقاء جهازك مفتوحًا أيامًا: أرفق معه ملف GitHub Actions
    المرفق (telecom_mapper.yml) في مستودع GitHub عام مجاني (لا يحتاج بطاقة
    ائتمان لحساب GitHub أو للخطة المجانية على المستودعات العامة). السكربت
    مبني أصلًا على الحفظ/الاستئناف (checkpoint) فيعمل بشكل طبيعي عبر عدة
    تشغيلات مجدولة قصيرة (كل تشغيل GitHub Actions محدود بـ6 ساعات كحد أقصى).

المصدر: RIPEstat Data API من RIPE NCC (مجاني بالكامل، بلا حساب/مفتاح API)
        https://stat.ripe.net/docs/data-api/

⚠️ التصنيف heuristic وليس مضمونًا 100%. حجم الكتلة ليس مؤشرًا حتميًا (فقط
   ملاحظة أولوية إضافية عند بقاء التصنيف "غير محدد"). راجع عيّنة يدويًا قبل
   الاعتماد الكامل على النتائج في أي استخدام حسّاس.

المتطلبات: Python 3.9+ فقط (لا مكتبات خارجية). رُفعت من 3.7 إلى 3.9 هنا
لاستخدام cancel_futures عند الإيقاف اليدوي (Ctrl+C) بشكل أنظف.

الاستخدام:
  python3 telecom_network_mapper.py
==========================================================================
"""

import ipaddress
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlencode

# =======================================================================
# 1) إعدادات عامة
# =======================================================================
RIPESTAT_BASE = "https://stat.ripe.net/data"
SOURCEAPP = "telecom-network-mapper"
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30       # ثانية، لكل طلب RIPEstat

OUTPUT_PATH = "telecom_networks.json"
CHECKPOINT_PATH = "checkpoint.json"

TEST_LIMIT = None          # مثال: 3 لمعالجة أول 3 دول فقط أثناء التجربة
ONLY_REGIONS = None        # مثال: ["Central Asia", "Southeast Asia"]

USE_REVERSE_DNS = True     # تعطيله كليًا = اعتماد على RIR فقط (الأسرع)
RDNS_MODE = "only_if_unclear"   # "always" | "only_if_unclear" | "never"
RDNS_SAMPLES = 5
RDNS_TIMEOUT = 2           # ثانية لكل استعلام PTR (best-effort فقط، غير مضمون الالتزام به داخليًا)
RDNS_BATCH_TIMEOUT = 4     # ثانية: سقف صارم فعلي لكل دفعة عيّنات كتلة واحدة (راجع classify_from_rdns)

LARGE_IPV4_PREFIXLEN = 15  # /15 فأكبر (IPv4) = "كبيرة جدًا" لملاحظة أولوية فقط

# --- ضبط التزامن: هذه الأرقام هي المفتاح الحقيقي للسرعة ---
COUNTRY_WORKERS = 6            # عدد الدول المُعالَجة بالتوازي
WORKERS_PER_COUNTRY = 15       # خيوط كل جولة عمل داخل الدولة الواحدة
RIPESTAT_MAX_CONCURRENT = 8    # قيد فعلي (Semaphore) على طلبات RIPEstat المتزامنة
DNS_MAX_CONCURRENT = 40        # مجمّع خيوط PTR المشترك عالميًا (لا يمر عبر RIPEstat)

_ripestat_semaphore = threading.Semaphore(RIPESTAT_MAX_CONCURRENT)
DNS_EXECUTOR = ThreadPoolExecutor(max_workers=DNS_MAX_CONCURRENT)

# علم مشترك بين كل الخيوط (الرئيسي والداخلية) لطلب إيقاف لطيف وسريع.
# مهم: الإشارات (signal) في بايثون تصل للخيط الرئيسي فقط، فالاعتماد على
# استثناء وحده لا يوقف الخيوط الداخلية (مثل تصنيف مئات الكتل المتبقية
# لدولة كبيرة) - لذلك كل حلقة عمل (خارجية وداخلية) تفحص هذا العلم بنفسها
# لتتوقف عن قبول/انتظار عمل جديد فورًا، بدل انتظار كل العمل المتراكم لدولة
# قد تحوي آلاف الكتل (وهو ما كان يسبب تأخر الإيقاف حتى الحد الأقصى الصارم
# لمنصة الاستضافة بدل التوقف اللطيف المبكر المقصود).
SHUTDOWN_EVENT = threading.Event()


def _handle_termination_signal(signum, frame):
    SHUTDOWN_EVENT.set()


signal.signal(signal.SIGTERM, _handle_termination_signal)
signal.signal(signal.SIGINT, _handle_termination_signal)

# =======================================================================
# 2) المناطق والدول (رموز ISO 3166-1 alpha-2)
# =======================================================================
REGIONS = {
    "Southeast Asia": {
        "BN": "Brunei", "KH": "Cambodia", "ID": "Indonesia", "LA": "Laos",
        "MY": "Malaysia", "MM": "Myanmar", "PH": "Philippines", "SG": "Singapore",
        "TH": "Thailand", "TL": "Timor-Leste", "VN": "Vietnam",
    },
    "Central Asia": {
        "KZ": "Kazakhstan", "KG": "Kyrgyzstan", "TJ": "Tajikistan",
        "TM": "Turkmenistan", "UZ": "Uzbekistan",
    },
    "Africa": {
        "DZ": "Algeria", "AO": "Angola", "BJ": "Benin", "BW": "Botswana",
        "BF": "Burkina Faso", "BI": "Burundi", "CV": "Cabo Verde", "CM": "Cameroon",
        "CF": "Central African Republic", "TD": "Chad", "CG": "Republic of the Congo",
        "CD": "Democratic Republic of the Congo", "DJ": "Djibouti", "EG": "Egypt",
        "GQ": "Equatorial Guinea", "ER": "Eritrea", "SZ": "Eswatini", "ET": "Ethiopia",
        "GA": "Gabon", "GM": "Gambia", "GH": "Ghana", "GN": "Guinea",
        "GW": "Guinea-Bissau", "CI": "Ivory Coast", "KE": "Kenya", "LS": "Lesotho",
        "LR": "Liberia", "LY": "Libya", "MW": "Malawi", "ML": "Mali",
        "MR": "Mauritania", "MA": "Morocco", "MZ": "Mozambique", "NA": "Namibia",
        "NE": "Niger", "NG": "Nigeria", "RW": "Rwanda", "ST": "Sao Tome and Principe",
        "SN": "Senegal", "SL": "Sierra Leone", "SO": "Somalia", "ZA": "South Africa",
        "SS": "South Sudan", "SD": "Sudan", "TZ": "Tanzania", "TG": "Togo",
        "TN": "Tunisia", "UG": "Uganda", "ZM": "Zambia", "ZW": "Zimbabwe",
    },
    "Eastern Europe": {
        "BY": "Belarus", "BG": "Bulgaria", "CZ": "Czechia", "HU": "Hungary",
        "MD": "Moldova", "PL": "Poland", "RO": "Romania", "RU": "Russia",
        "SK": "Slovakia", "UA": "Ukraine",
    },
    "Pacific Island States": {
        "FJ": "Fiji", "KI": "Kiribati", "MH": "Marshall Islands",
        "FM": "Micronesia", "NR": "Nauru", "PW": "Palau",
        "PG": "Papua New Guinea", "WS": "Samoa", "SB": "Solomon Islands",
        "TO": "Tonga", "TV": "Tuvalu", "CK": "Cook Islands", "NU": "Niue",
    },
    "Caribbean Island States": {
        "AG": "Antigua and Barbuda", "BS": "Bahamas", "BB": "Barbados",
        "CU": "Cuba", "DM": "Dominica", "DO": "Dominican Republic",
        "GD": "Grenada", "HT": "Haiti", "JM": "Jamaica",
        "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
        "VC": "Saint Vincent and the Grenadines", "TT": "Trinidad and Tobago",
    },
    "Indian Ocean Island States": {
        "KM": "Comoros", "MG": "Madagascar", "MV": "Maldives",
        "MU": "Mauritius", "SC": "Seychelles",
    },
    "South America": {
        "AR": "Argentina", "BO": "Bolivia", "BR": "Brazil", "CL": "Chile",
        "CO": "Colombia", "EC": "Ecuador", "GY": "Guyana", "PY": "Paraguay",
        "PE": "Peru", "SR": "Suriname", "UY": "Uruguay", "VE": "Venezuela",
    },
}

# =======================================================================
# 3) كلمات مفتاحية للتعرف على شركات الاتصالات من اسم مالك رقم AS
# =======================================================================
GENERIC_KEYWORDS = [
    "telecom", "telekom", "telecommunicat", "telco", "teleco",
    "mobile", "wireless", "cellular", "gsm", "cdma",
    "communications", "comunicaciones", "comunicacoes", "comms",
    "broadband", "fiber", "fibre", "cable tv", "cablevision", "satellite",
    "internet service", "data services", "backbone", "national network",
    "posts and telecommunications", "ptt ", " ptt",
]
BRAND_KEYWORDS = [
    "mtn", "orange", "airtel", "vodafone", "vodacom", "safaricom", "econet",
    "beeline", "megafon", " mts ", "tele2", "kcell", "turkcell", "telkom",
    "telkomsel", "indosat", "xl axiata", "viettel", "true move", " ais ",
    "dtac", "smart communications", "globe telecom", "pldt", "singtel",
    "starhub", "digicel", "flow ", "cable and wireless", "claro", "movistar",
    "telefonica", "entel", "tigo", "millicom", "ncell", "beeline",
]
TELECOM_KEYWORDS = [k.lower() for k in GENERIC_KEYWORDS + BRAND_KEYWORDS]


def is_telecom(holder_name):
    """يتحقق إن كان اسم مالك AS يحتوي كلمة دالة على شركة اتصالات/إنترنت."""
    if not holder_name:
        return False
    name = f" {holder_name.lower()} "
    return any(kw in name for kw in TELECOM_KEYWORDS)


# =======================================================================
# 4) قواعد وكلمات تصنيف كل كتلة (بنية تحتية / مشتركين)
# =======================================================================
CGNAT_RANGE = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598

CUSTOMER_KEYWORDS = [
    "customer", "customers", "subscriber", "subscribers", "client",
    "end user", "end-user", "enduser", "residential", "consumer",
    "home user", "home-user", "dial-up", "dialup",
    "dsl", "adsl", "vdsl", "xdsl", "cable modem", "docsis",
    "gpon", "ftth", "fttx", "fiber-cust", "fibre-cust", "broadband-cust",
    "mobile-cust", "mobile customer", "gprs", "3g pool", "4g pool",
    "5g pool", "lte pool", "lte-pool", "umts", "apn pool", "data-pool",
    "cgn", "cgnat", "nat44", "carrier grade nat", "carrier-grade-nat",
    "dhcp pool", "dhcp-pool", "dynamic pool", "dynamic-pool",
    "dynamic ip", "dynamic-ip", "static pool", "static-pool",
    "access network", "access-network", "bras pool", "bras-pool",
    "bng pool", "bng-pool", "wifi hotspot", "wifi-hotspot",
    "public wifi", "public-wifi", "reallocated", "reassigned",
]
INFRA_KEYWORDS = [
    "core network", "core-network", "backbone", "infrastructure",
    "infra-", "-infra", "noc", "network operations",
    "datacenter", "data center", "data-center", "colocation", "colo-",
    "peering", "internet exchange", " ix ", "-ix-", "transit",
    "management network", "mgmt", "out of band", "oob-",
    "headquarters", " hq ", "corporate", "admin office",
    "signaling", "signalling", "ims core", "voip core", "voip-core",
    "core router", "core-router", "backbone router",
    "point of presence", "server farm", "server-farm",
    "hosting infrastructure",
]
DOWNSTREAM_STATUS_HINTS = ["sub-allocated", "suballocated", "lir-partitioned"]

DESCRIPTIVE_KEYS = {"netname", "descr", "description", "orgname",
                     "organization", "name", "remarks"}
STATUS_KEYS = {"status", "nettype"}

PTR_CUSTOMER_HINTS = [
    "dyn", "dynamic", "pool", "dsl", "adsl", "vdsl", "cable", "docsis",
    "gpon", "ftth", "cust", "customer", "cpe", "static-ip", "broadband",
    "mobile", "3g", "4g", "5g", "lte", "gprs", "umts", "residential",
    "dial", "subscriber", "bband",
]
PTR_INFRA_HINTS = [
    "core", "backbone", "router", "rtr", "switch", "gateway",
    "noc", "loopback", "peer", "transit", "mgmt", "vpn",
    "firewall", "ns1", "ns2", "mail", "smtp", " mx", "www",
    "bras", "bng", "colo", "datacenter", "dc-",
]

CLASSIFICATION_LEGEND = {
    "بنية تحتية": "مؤشرات على استخدام تشغيلي/داخلي للشركة (Core, Backbone, NOC, Datacenter...)",
    "مشتركين": "مؤشرات على تجمّع عناوين مخصّص لعملاء/مشتركين (DSL/Cable/GPON/Mobile/CGNAT...)",
    "غير محدد": "لا توجد مؤشرات كافية من أي مصدر (RIR أو PTR) - يحتاج مراجعة يدوية",
}


def classify_from_registry(text_blob, status_blob, network_obj):
    """الإشارة الأولى: نص RIR (netname/descr) + status + قاعدة CGNAT الحتمية."""
    if network_obj is not None:
        try:
            if network_obj.overlaps(CGNAT_RANGE):
                return "مشتركين", "ضمن نطاق CGNAT المشترك (RFC 6598)"
        except (TypeError, ValueError):
            pass

    blob = f" {text_blob.lower()} "
    cust_hit = next((k for k in CUSTOMER_KEYWORDS if k in blob), None)
    infra_hit = next((k for k in INFRA_KEYWORDS if k in blob), None)

    if cust_hit and not infra_hit:
        return "مشتركين", f"كلمة مفتاحية RIR: {cust_hit}"
    if infra_hit and not cust_hit:
        return "بنية تحتية", f"كلمة مفتاحية RIR: {infra_hit}"
    if infra_hit and cust_hit:
        return "مشتركين", f"تعارض كلمات RIR ({infra_hit}/{cust_hit}) - رُجّح الاستبعاد احتياطًا"

    status_l = f" {status_blob.lower()} "
    hit = next((h for h in DOWNSTREAM_STATUS_HINTS if h in status_l), None)
    if hit:
        return "مشتركين", f"status يدل على تفويض لجهة تالية: {status_blob.strip()}"

    return "غير محدد", "لا توجد مؤشرات كافية في netname/descr/status"


def should_run_rdns(reg_label):
    if not USE_REVERSE_DNS or RDNS_MODE == "never":
        return False
    if RDNS_MODE == "only_if_unclear":
        return reg_label == "غير محدد"
    return True  # "always"


def sample_ips(network_obj, max_samples):
    """يختار عيّنة عناوين موزّعة داخل الكتلة (أول/وسط/آخر...) بدل فحص الكل."""
    total = network_obj.num_addresses
    if total <= max_samples:
        return [str(ip) for ip in network_obj]
    step = total // max_samples
    net_int = int(network_obj.network_address)
    offsets = sorted({min(i * step + step // 2, total - 1) for i in range(max_samples)})
    return [str(ipaddress.ip_address(net_int + off)) for off in offsets]


def reverse_dns_lookup(ip):
    """استعلام PTR فعلي (يتطلب اتصال شبكة عند تشغيل السكربت لديك)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        return None


def ip_octets_in_hostname(ip, hostname):
    """يتحقق إن كان اسم PTR "مُقولَبًا" (يحوي أجزاء رقمية من العنوان نفسه) -
    السمة المميزة لأسماء PTR المولَّدة آليًا لتجمّعات المشتركين الكبيرة."""
    parts = ip.split(".")
    return sum(1 for p in parts if p in hostname) >= 2


def classify_from_rdns(network_obj):
    """الإشارة الثانية: أنماط PTR. العيّنات الخمس تُفحص بالتوازي عبر DNS_EXECUTOR
    المشترك عالميًا (لا تمر عبر Semaphore الخاص بـ RIPEstat).

    ⚠️ ملاحظة مهمة: دالة socket.gethostbyaddr في بايثون معروف عنها أنها لا
    تلتزم دائمًا فعليًا بـ socket.setdefaulttimeout() (قيد موثّق في مكتبة
    بايثون القياسية، خصوصًا عند عدم وجود سجل PTR أصلًا وهو أمر شائع جدًا).
    لذلك لا نعتمد على ذلك وحده هنا: نفرض سقفًا زمنيًا صارمًا مستقلًا على
    الانتظار نفسه عبر as_completed(timeout=...)، فحتى لو عَلِقت بعض
    الاستعلامات فعليًا في الخلفية، السكربت لا ينتظرها ويكمل بما توفر فقط -
    هذا ضروري لمنع تعليق التنفيذ بالكامل لساعات عند كتل كثيرة بلا PTR."""
    samples = sample_ips(network_obj, RDNS_SAMPLES)

    futures = {DNS_EXECUTOR.submit(reverse_dns_lookup, ip): ip for ip in samples}
    resolved_map = {}
    try:
        for future in as_completed(futures, timeout=RDNS_BATCH_TIMEOUT):
            ip = futures[future]
            try:
                resolved_map[ip] = future.result()
            except Exception:
                resolved_map[ip] = None
    except TimeoutError:
        pass  # بعض العيّنات لم تُكمَل خلال السقف الزمني - نكمل بما توفر فقط
              # (الاستعلامات العالقة تبقى تعمل بالخلفية دون انتظارها، وهذا
              # مقبول: بايثون لا يمكنه إنهاء خيط قسرًا، لكن المهم ألا يُعطَّل
              # تقدّم بقية الكتل بسبب استعلام واحد عالق)

    cust_votes = infra_votes = 0
    hostnames_found = []
    for ip in samples:  # نحافظ على ترتيب العيّنات الأصلي، لا ترتيب اكتمال الخيوط
        hostname = resolved_map.get(ip)
        if not hostname:
            continue
        h = hostname.lower().rstrip(".")
        hostnames_found.append(hostname)
        if ip_octets_in_hostname(ip, h) or any(k in h for k in PTR_CUSTOMER_HINTS):
            cust_votes += 1
        elif any(k in h for k in PTR_INFRA_HINTS):
            infra_votes += 1

    resolved = len(hostnames_found)
    base = f"({resolved}/{len(samples)} عناوين لها PTR)"
    examples = ", ".join(hostnames_found[:3])
    if resolved == 0:
        return "غير محدد", f"لا توجد سجلات PTR {base}", hostnames_found
    if cust_votes > infra_votes:
        return "مشتركين", f"أنماط PTR لمشتركين {base}: {examples}", hostnames_found
    if infra_votes > cust_votes:
        return "بنية تحتية", f"أنماط PTR لبنية تحتية {base}: {examples}", hostnames_found
    return "غير محدد", f"أنماط PTR غير حاسمة {base}: {examples}", hostnames_found


def combine_classifications(reg_label, reg_reason, rdns_label, rdns_reason):
    """يدمج إشارة RIR وإشارة PTR: اتفاق = ثقة أعلى، تعارض = يُترك للمراجعة اليدوية."""
    if reg_label == rdns_label:
        if reg_label == "غير محدد":
            return "غير محدد", f"لا توجد إشارة حاسمة | RIR: {reg_reason} | PTR: {rdns_reason}"
        return reg_label, f"RIR وPTR متّفقان | RIR: {reg_reason} | PTR: {rdns_reason}"
    if reg_label != "غير محدد" and rdns_label == "غير محدد":
        return reg_label, f"إشارة RIR (الأقوى) | RIR: {reg_reason} | PTR: {rdns_reason}"
    if rdns_label != "غير محدد" and reg_label == "غير محدد":
        return rdns_label, f"إشارة PTR (الأقوى) | RIR: {reg_reason} | PTR: {rdns_reason}"
    return ("غير محدد",
            f"تعارض بين RIR ({reg_label}) وPTR ({rdns_label}) - يحتاج مراجعة يدوية "
            f"| RIR: {reg_reason} | PTR: {rdns_reason}")


def is_very_large_ipv4_block(network_obj):
    return (network_obj is not None and network_obj.version == 4
            and network_obj.prefixlen <= LARGE_IPV4_PREFIXLEN)


# =======================================================================
# 5) الاتصال بـ RIPEstat (مُقيَّد بـ Semaphore عالمي، مستقل عن عدد الخيوط)
# =======================================================================
def http_get_json(data_call, params):
    """طلب GET إلى RIPEstat مع محاولات إعادة عند فشل الشبكة. الـ Semaphore
    يُحجز فقط أثناء الطلب الفعلي، وليس أثناء انتظار إعادة المحاولة، حتى لا
    يُعطَّل خيط آخر بلا داعٍ."""
    params = dict(params)
    params["sourceapp"] = SOURCEAPP
    url = f"{RIPESTAT_BASE}/{data_call}/data.json?{urlencode(params)}"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "telecom-network-mapper/1.0"}
            )
            with _ripestat_semaphore:
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            if attempt == MAX_RETRIES:
                print(f"    ! فشل الطلب نهائيًا ({data_call}, {params.get('resource')}): {e}",
                      file=sys.stderr)
                return None
            time.sleep(2 ** attempt)
    return None


def get_country_asns(country_code):
    data = http_get_json("country-resource-list", {"resource": country_code})
    if not data or data.get("status") != "ok":
        return []
    return data["data"]["resources"].get("asn", [])


def get_as_holder(asn):
    data = http_get_json("as-overview", {"resource": f"AS{asn}"})
    if not data or data.get("status") != "ok":
        return None
    return data["data"].get("holder")


def get_announced_prefixes(asn):
    data = http_get_json("announced-prefixes", {"resource": f"AS{asn}"})
    if not data or data.get("status") != "ok":
        return []
    return [p["prefix"] for p in data["data"].get("prefixes", []) if "prefix" in p]


def fetch_whois_metadata(prefix):
    """يستخرج نصوص الوصف (netname/descr/...) وقيمة status لكتلة عنوان."""
    data = http_get_json("whois", {"resource": prefix})
    if not data or data.get("status") != "ok":
        return "", ""
    text_parts, status_parts = [], []
    for record in data.get("data", {}).get("records", []):
        for entry in record:
            key = (entry.get("key") or "").strip().lower()
            value = (entry.get("value") or "").strip()
            if not value:
                continue
            if key in DESCRIPTIVE_KEYS:
                text_parts.append(value)
            elif key in STATUS_KEYS:
                status_parts.append(value)
    return " | ".join(text_parts), " | ".join(status_parts)


# =======================================================================
# 6) معالجة كتلة واحدة / شركة اتصالات واحدة / دولة واحدة
# =======================================================================
def classify_prefix_full(prefix):
    """يجمع بيانات وتصنيف كتلة واحدة كاملة (تُستدعى بتزامن لكل كتل الدولة)."""
    try:
        network_obj = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        network_obj = None

    text_blob, status_blob = fetch_whois_metadata(prefix)
    reg_label, reg_reason = classify_from_registry(text_blob, status_blob, network_obj)

    if reg_label == "مشتركين" and "CGNAT" in reg_reason:
        rdns_label, rdns_reason, hostnames = (
            "مشتركين", "تخطّي فحص PTR (نطاق CGNAT حتمي أصلًا)", []
        )
    elif network_obj is not None and should_run_rdns(reg_label):
        rdns_label, rdns_reason, hostnames = classify_from_rdns(network_obj)
    else:
        rdns_label, rdns_reason, hostnames = (
            "غير محدد",
            f"تخطّي فحص PTR (RDNS_MODE={RDNS_MODE})",
            [],
        )

    label, reason = combine_classifications(reg_label, reg_reason, rdns_label, rdns_reason)

    if label == "غير محدد" and is_very_large_ipv4_block(network_obj):
        reason += (f" | تنبيه: كتلة IPv4 كبيرة جدًا (/{network_obj.prefixlen}) - "
                   "الأرجح إحصائيًا (وليس مؤكدًا) أنها مجمّع مشتركين، أولوية للمراجعة اليدوية")

    return {
        "prefix": prefix,
        "prefix_size": f"/{network_obj.prefixlen}" if network_obj else None,
        "classification": label,
        "classification_reason": reason,
        "rir_netname_descr": text_blob,
        "rir_status": status_blob,
        "ptr_samples": hostnames[:5],
    }


def get_telecom_operators_for_country(cc):
    """المرحلة أ: يُرجع [{asn, holder, prefix_list}] لمشغّلي اتصالات الدولة."""
    if SHUTDOWN_EVENT.is_set():
        return [], 0

    asns = get_country_asns(cc)
    if not asns:
        return [], 0

    holders = {}
    executor = ThreadPoolExecutor(max_workers=WORKERS_PER_COUNTRY)
    try:
        futures = {executor.submit(get_as_holder, asn): asn for asn in asns}
        for future in as_completed(futures):
            if SHUTDOWN_EVENT.is_set():
                break
            asn = futures[future]
            try:
                holders[asn] = future.result()
            except Exception as e:
                print(f"    ! خطأ AS{asn} (holder): {e}", file=sys.stderr)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    telecom_asns = {asn: holder for asn, holder in holders.items() if is_telecom(holder)}
    if not telecom_asns or SHUTDOWN_EVENT.is_set():
        return [], len(asns)

    prefix_map = {}
    executor = ThreadPoolExecutor(max_workers=WORKERS_PER_COUNTRY)
    try:
        futures = {executor.submit(get_announced_prefixes, asn): asn for asn in telecom_asns}
        for future in as_completed(futures):
            if SHUTDOWN_EVENT.is_set():
                break
            asn = futures[future]
            try:
                prefix_map[asn] = future.result()
            except Exception as e:
                print(f"    ! خطأ AS{asn} (prefixes): {e}", file=sys.stderr)
                prefix_map[asn] = []
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return (
        [{"asn": asn, "holder": holder, "prefix_list": prefix_map.get(asn, [])}
         for asn, holder in telecom_asns.items() if asn in prefix_map],
        len(asns),
    )


def classify_country_operators(operators):
    """المرحلة ب: يصنّف كل كتل كل مشغّلي الدولة بتزامن على مستوى الكتلة الواحدة."""
    flat_jobs = [
        (op_idx, prefix)
        for op_idx, op in enumerate(operators)
        for prefix in op["prefix_list"]
    ]

    results_by_job = {}
    executor = ThreadPoolExecutor(max_workers=WORKERS_PER_COUNTRY)
    try:
        futures = {
            executor.submit(classify_prefix_full, prefix): (op_idx, prefix)
            for op_idx, prefix in flat_jobs
        }
        for future in as_completed(futures):
            if SHUTDOWN_EVENT.is_set():
                break
            op_idx, prefix = futures[future]
            try:
                results_by_job[(op_idx, prefix)] = future.result()
            except Exception as e:
                print(f"    ! خطأ تصنيف {prefix}: {e}", file=sys.stderr)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    for op_idx, op in enumerate(operators):
        op["prefixes"] = [
            results_by_job[(op_idx, prefix)]
            for prefix in op["prefix_list"]
            if (op_idx, prefix) in results_by_job
        ]
        del op["prefix_list"]
    return operators


def process_country(cc):
    operators, asn_count = get_telecom_operators_for_country(cc)
    if operators:
        operators = classify_country_operators(operators)
    return operators, asn_count


# =======================================================================
# 7) حفظ/تحميل التقدم والنتائج (JSON)
# =======================================================================
def load_checkpoint():
    if os.path.exists(CHECKPOINT_PATH):
        try:
            with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data.get("done_countries"), list):
                return data
        except (json.JSONDecodeError, OSError, AttributeError) as e:
            print(f"تحذير: تعذّرت قراءة {CHECKPOINT_PATH} الموجود ({e})، سيُعاد إنشاؤه.",
                  file=sys.stderr)
    return {"done_countries": []}


def save_checkpoint(state):
    with open(CHECKPOINT_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def load_existing_results():
    if os.path.exists(OUTPUT_PATH):
        try:
            with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data.get("regions"), dict):
                return data
        except (json.JSONDecodeError, OSError) as e:
            print(f"تحذير: تعذّرت قراءة {OUTPUT_PATH} الموجود ({e})، سيُعاد إنشاؤه.",
                  file=sys.stderr)
    return {
        "metadata": {
            "source": "RIPEstat Data API (RIPE NCC) - https://stat.ripe.net/docs/data-api/",
            "classification_legend": CLASSIFICATION_LEGEND,
            "classification_method": (
                "دمج نص تسجيل RIR (netname/descr/status) مع أنماط PTR (Reverse DNS، "
                f"وضع RDNS_MODE={RDNS_MODE}). تصنيف تخميني وليس مضمونًا 100%، راجع عيّنة "
                "يدويًا قبل الاعتماد الكامل عليه."
            ),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "regions": {},
    }


def save_results(results):
    """كتابة آمنة: ملف مؤقت ثم استبدال ذرّي، لتفادي إتلاف JSON عند مقاطعة الكتابة."""
    results["metadata"]["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp_path = OUTPUT_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, OUTPUT_PATH)


# =======================================================================
# 8) البرنامج الرئيسي (عدة دول بالتوازي)
# =======================================================================
def main():
    if USE_REVERSE_DNS:
        socket.setdefaulttimeout(RDNS_TIMEOUT)

    state = load_checkpoint()
    done = set(state["done_countries"])
    results = load_existing_results()

    # حفظ فوري: يضمن وجود telecom_networks.json وcheckpoint.json على القرص
    # من أول ثانية، حتى لو حدث خطأ غير متوقع لاحقًا (مهم لخطوة commit/push
    # في GitHub Actions التي تعتمد على وجود هذين الملفين).
    save_checkpoint(state)
    save_results(results)

    regions_to_process = {
        r: c for r, c in REGIONS.items() if not ONLY_REGIONS or r in ONLY_REGIONS
    }
    country_list = [
        (region, cc, cname)
        for region, countries in regions_to_process.items()
        for cc, cname in countries.items()
    ]
    if TEST_LIMIT:
        country_list = country_list[:TEST_LIMIT]

    pending = [(region, cc, cname) for region, cc, cname in country_list
               if f"{region}|{cc}" not in done]
    total = len(country_list)
    print(f"إجمالي الدول: {total} | مُنجز مسبقًا: {total - len(pending)} | "
          f"متبقٍ: {len(pending)} | معالجة {COUNTRY_WORKERS} دول بالتوازي "
          f"(RDNS_MODE={RDNS_MODE})")

    state_lock = threading.Lock()
    completed = 0

    def handle_country(region, cc, cname):
        nonlocal completed
        operators, asn_count = process_country(cc)
        with state_lock:
            results["regions"].setdefault(region, {})[cc] = {
                "country_name": cname,
                "telecom_operators": operators,
            }
            save_results(results)
            done.add(f"{region}|{cc}")
            state["done_countries"] = sorted(done)
            save_checkpoint(state)
            completed += 1

            total_prefixes = sum(len(op["prefixes"]) for op in operators)
            infra_count = sum(1 for op in operators for p in op["prefixes"]
                               if p["classification"] == "بنية تحتية")
            cust_count = sum(1 for op in operators for p in op["prefixes"]
                              if p["classification"] == "مشتركين")
            print(
                f"[{completed}/{len(pending)}] {region} / {cname} ({cc}): "
                f"{asn_count} AS، {len(operators)} شركة اتصالات، {total_prefixes} كتلة "
                f"(بنية تحتية={infra_count}, مشتركين={cust_count}, "
                f"غير محدد={total_prefixes - infra_count - cust_count})"
            )

    executor = ThreadPoolExecutor(max_workers=COUNTRY_WORKERS)
    warned = False
    try:
        futures = {
            executor.submit(handle_country, region, cc, cname): (region, cc, cname)
            for region, cc, cname in pending
        }
        for future in as_completed(futures):
            if SHUTDOWN_EVENT.is_set() and not warned:
                warned = True
                print("\nطُلب إيقاف (Ctrl+C أو SIGTERM، غالبًا timeout خارجي). الدول قيد "
                      "التنفيذ الآن ستتوقف عن أي عمل جديد فورًا وتُحفظ نتائجها الجزئية "
                      "(أعد تشغيل السكربت لاحقًا للاستئناف من حيث توقف).")
            region, cc, cname = futures[future]
            try:
                future.result()
            except Exception as e:
                print(f"    ! خطأ في معالجة {cname} ({cc}): {e}", file=sys.stderr)
    finally:
        executor.shutdown(wait=not SHUTDOWN_EVENT.is_set(), cancel_futures=True)
        save_checkpoint(state)
        save_results(results)
        DNS_EXECUTOR.shutdown(wait=False, cancel_futures=True)

    status = "توقف يدويًا/خارجيًا (تقدّم جزئي محفوظ)" if SHUTDOWN_EVENT.is_set() else "انتهى بالكامل"
    print(f"\n{status}. النتائج في: {os.path.abspath(OUTPUT_PATH)}")


if __name__ == "__main__":
    main()
