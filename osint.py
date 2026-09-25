#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT-Lookup - Terminal-Tool für passive Recherche auf öffentlichen Quellen
Nur lesen, kein Login, keine Passwörter, nichts wird verändert.

Module:
  RECHERCHE
    ip    <ip>          IP-Lookup: Standort, Netz, Routing, Reputation
                        (leer = eigene IP)
    dns   <domain>      DNS: A, AAAA, CNAME, MX, NS, TXT, SOA (DoH)
    whois <domain>      RDAP/WHOIS: Registrar, Status, Daten, Abuse
    user  <name>        Username auf 9 Plattformen prüfen
    mail  <adresse>     E-Mail-Triage: Anbieter, SPF/DMARC/BIMI/MTA-STS,
                        DNSSEC, Domainalter, öffentliches Gravatar-Profil
    archive <url>       Wayback Machine: Snapshots
    phone <nummer>      Rufnummer: Land, Typ, Anbieter, Zeitzone, Wählhilfe
  NETZ & TECHNIK
    subnet <cidr>       Subnetz-Rechner (z.B. 192.168.1.0/24)
    hash  <text>        Hash erkennen (MD5/SHA-1/SHA-256...) oder erzeugen
    pw    <passwort>    Stärke-Check, komplett lokal (nichts wird gesendet)
    mac   <mac-adresse> MAC-Adress-Vendor (OUI)
    report <ip>         Abuse-Report: fertige Meldung an den Provider
  WEB
    redirect <url>      Redirect-Kette / URL-Entkürzung auflösen
    headers <url>       HTTP-Header + Security-Header-Bewertung
    ptr   <ip>          Reverse-DNS (PTR)
    cve   <suchbegriff> CVE-Suche über NVD

Aufruf:  python osint.py <modul> <ziel>   oder   start.bat (Menü)
"""

import hashlib
import ipaddress
import json
import math
import os
import random
import re
import shutil
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from datetime import datetime, timedelta, timezone

try:
    import phonenumbers as pn
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geo
    from phonenumbers import timezone as pn_tz
except ImportError:                       # optionale Abhängigkeit
    pn = None

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

# Windows: Ausgabe erzwingt UTF-8 (sonst crasht cp1252 bei Umlauten/Boxen)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

USE_COLOR = ((sys.stdout.isatty() or os.environ.get("OSINT_COLOR"))
             and not os.environ.get("NO_COLOR"))


# ---------------------------------------------------------------- Farben
def col(t, code):
    return f"\033[{code}m{t}\033[0m" if USE_COLOR else str(t)


def bold(t):
    return col(t, "1")


def cyan(t):
    return col(t, "36")


def green(t):
    return col(t, "32")


def yellow(t):
    return col(t, "33")


def red(t):
    return col(t, "31")


def magenta(t):
    return col(t, "35")


def blue(t):
    return col(t, "34")


def dim(t):
    return col(t, "2")


# ---------------------------------------------------------------- HTTP
def request(url, method="GET", data=None, headers=None, timeout=20):
    """Gibt (status_code, text) zurück – wirft nie eine Exception."""
    hdr = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, text/html, */*",
        "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
    }
    if headers:
        hdr.update(headers)

    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdr["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception as e:
        return 0, str(e)


def get_json(url, **kw):
    status, text = request(url, **kw)
    if status == 200:
        try:
            return status, json.loads(text)
        except json.JSONDecodeError:
            return status, None
    return status, None


def dns_query(name, rtype, timeout=15):
    """Antworten von Google DoH: Liste von dicts oder None."""
    status, data = get_json(
        f"https://dns.google/resolve?name={urllib.parse.quote(str(name))}"
        f"&type={rtype}", timeout=timeout)
    if status != 200 or not isinstance(data, dict):
        return None
    return data.get("Answer") or []


# ---------------------------------------------------------------- Spinner
class Spinner:
    """Läuft nur in einer echten Konsole – bei Output-Umleitung still."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, text="abfrage"):
        self.text = text
        self.enabled = sys.stdout.isatty()
        self._stop = threading.Event()
        self._thread = None
        self._done = False

    def _run(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write("\r" + col(frame, "36") + " " + dim(self.text))
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.09)

    def start(self):
        if self.enabled:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def stop(self):
        if self._done:
            return
        self._done = True
        if not self.enabled:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


# ---------------------------------------------------------------- Layout
def fmt_num(n):
    try:
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(n)


LABEL_W = 17          # Spaltenbreite für die Beschriftungen
RULE_W = 44           # Breite der Abschnittslinien (wie die Kopfbox)


def row(label, value, color=bold):
    """Eine Ausgabezeile: gedämpftes Label, markanter Wert."""
    print(f"   {dim(str(label).ljust(LABEL_W))} {color(value)}")


def section(title):
    """Abschnitts-Überschrift mit Auslauf nach rechts."""
    pad = max(6, RULE_W - len(str(title)) - 4)
    print(f"\n   {cyan('◆')} {bold(title)} {dim('─' * pad)}")


def header(title, subtitle=None):
    title = str(title)
    subtitle = str(subtitle) if subtitle else None
    longest = [len(title)] + ([len(subtitle)] if subtitle else [])
    width = max(42, max(longest) + 2)          # Anzahl Bindestriche
    inner = width - 1
    print()
    print(bold(magenta("  ╭" + "─" * width + "╮")))
    print(magenta("  │ ") + bold(title.ljust(inner)) + magenta("│"))
    if subtitle:
        print(magenta("  │ ") + dim(subtitle.ljust(inner)) + magenta("│"))
    print(bold(magenta("  ╰" + "─" * width + "╯")))


def hint(text):
    """Hinweiszeile – wird auf die Fensterbreite umbrochen."""
    width = max(60, shutil.get_terminal_size((100, 30)).columns - 6)
    lines = textwrap.wrap(str(text), width) or [""]
    print()
    for i, line in enumerate(lines):
        prefix = f"   {cyan('»')} " if i == 0 else "     "
        print(f"{prefix}{dim(line)}")
    print()


def mark(ok, text=None, yes="ja", no="nein"):
    if ok:
        return green("  [+] " + (text or yes))
    return dim("  [-] " + (text or no))


def fmt_duration(seconds):
    units = [(31_557_600, "Jahr", "Jahre"), (86_400, "Tag", "Tage"),
             (3600, "Stunde", "Stunden"), (60, "Minute", "Minuten"),
             (1, "Sekunde", "Sekunden")]
    if seconds / 31_557_600 >= 1e12:
        return "≈ " + f"{seconds / 31_557_600:.1e}".replace(".", ",") + " Jahre"
    for factor, singular, plural in units:
        if seconds >= factor:
            value = seconds / factor
            word = singular if abs(value - 1) < 0.05 else plural
            number = f"{value:,.0f}".replace(",", ".") if value >= 10 \
                else f"{value:.1f}"
            return f"{number} {word}"
    return "< 1 Sekunde"


# ---------------------------------------------------------------- Startup
LOGO = [
    "    ____  ____  _____   ____  _   _ ",
    "   / ___||  _ \\|  ___| / ___|| | | |",
    "   \\___ \\| |_) | |_    \\___ \\| |_| |",
    "    ___) |  _ <|  _|    ___) |  _  |",
    "   |____/|_| \\_\\_|     |____/|_| |_|",
]

GLITCH = "▒░▒▓#@%&$*+=~^:"


def _glitch_line(line, delay=0.07):
    scrambled = "".join(random.choice(GLITCH) if c != " " else " "
                        for c in line)
    sys.stdout.write("\r" + dim(scrambled))
    sys.stdout.flush()
    time.sleep(delay)
    sys.stdout.write("\r" + cyan(bold(line)))
    sys.stdout.flush()


def _progress(label="quellen laden"):
    total = 30
    for i in range(0, 101, 4):
        filled = int(i / 100 * total)
        bar = green("█" * filled) + dim("░" * (total - filled))
        sys.stdout.write(f"\r   {bar} {bold(f'{i:>3d}%')}  {dim(label)}")
        sys.stdout.flush()
        time.sleep(0.025)
    sys.stdout.write("\n")


def startup():
    """Start-Animation – nur in der echten Konsole."""
    if not (sys.stdout.isatty() or os.environ.get("OSINT_ANIM")):
        return
    if os.name == "nt" and sys.stdout.isatty() and not os.environ.get("OSINT_ANIM"):
        os.system("cls")

    print()
    for line in LOGO:
        _glitch_line(line)
        print()
        time.sleep(0.03)

    print(f"      {dim('P A S S I V E   R E C H E R C H E   ·   N U R   L E S E N')}")
    print()
    _progress("öffentliche Quellen werden vorbereitet")

    checks = ["DNS/DoH", "RDAP", "NVD-CVE", "Wayback", "16 Module"]
    line = "   " + "   ".join(green("✓") + " " + dim(c) for c in checks)
    print(line)
    time.sleep(0.35)
    print()


# ---------------------------------------------------------------- 1) IP
def _ip_scope(addr):
    """Einordnung, was für eine Adresse das ist."""
    if addr.version == 4:
        if addr.is_loopback:
            return "Loopback (127/8)"
        if addr.is_link_local:
            return "Link-Local (169.254/16)"
        if addr.is_multicast:
            return "Multicast (224/4)"
        if addr.is_unspecified:
            return "unbestimmt (0.0.0.0)"
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            return "CGNAT (100.64/10)"
    if addr.is_private:
        return "privat/lokal (RFC1918)" if addr.version == 4 else "privat (ULA)"
    if addr.is_reserved:
        return "reserviert"
    return "global nutzbar"


EMERGENCY = {
    "DE": "112 (Feuerwehr) · 110 (Polizei)",
    "AT": "112 · 144 (Rettung) · 133 (Polizei)",
    "CH": "112 · 144 (Rettung) · 117 (Polizei)",
    "US": "911", "CA": "911", "GB": "999 · 112", "IE": "112 · 999",
    "FR": "112 · 15 (Sanität) · 17 (Polizei) · 18 (Feuer)",
    "ES": "112", "IT": "112 · 113 (Polizei)", "NL": "112", "BE": "112",
    "LU": "112", "DK": "112", "SE": "112", "NO": "112 · 110 (Polizei)",
    "FI": "112", "PL": "112 · 997 (Polizei)", "CZ": "112 · 158 (Polizei)",
    "SK": "112 · 158", "HU": "112 · 107", "RO": "112", "BG": "112",
    "PT": "112", "GR": "112 · 166", "TR": "112", "RU": "112 · 102 (Polizei)",
    "UA": "112", "JP": "110 (Polizei) · 119 (Feuer/Rettung)",
    "KR": "112 · 119", "AU": "000 · 112", "NZ": "111",
    "IN": "112", "CN": "110 · 120 · 119", "SG": "995 · 999",
    "MY": "999", "TH": "191 · 1669", "ID": "112 · 113", "PH": "911",
    "BR": "190 · 192 (Sanität)", "AR": "911 · 101", "CL": "133 · 131",
    "MX": "911", "CO": "123", "ZA": "10111 · 112", "IL": "100 · 101",
    "SA": "911 · 999", "AE": "999 · 998", "EG": "122 · 123",
}


def _haversine(lat1, lon1, lat2, lon2):
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dlam / 2) ** 2)
    return 2 * radius * math.asin(math.sqrt(a))


def _bearing(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlam = math.radians(lon2 - lon1)
    y = math.sin(dlam) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dlam)
    return (math.degrees(math.atan2(y, x)) + 360) % 360


def _compass(deg):
    dirs = ["N", "NNO", "NO", "ONO", "O", "OSO", "SO", "SSO",
            "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
    return dirs[int((deg + 11.25) // 22.5) % 16]


def _vcard_email(ent):
    for item in (ent.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "email" and item[3]:
            return item[3]
    return None


def _find_abuse(entities, depth=0):
    if depth > 3:
        return None
    for ent in entities or []:
        if "abuse" in (ent.get("roles") or []):
            mail = _vcard_email(ent)
            if mail:
                return mail
        found = _find_abuse(ent.get("entities"), depth + 1)
        if found:
            return found
    return None


def _find_role(entities, role):
    for ent in entities or []:
        if role in (ent.get("roles") or []):
            return ent.get("handle") or "-"
    return None


def _text_list(url, timeout=45):
    status, text = request(url, timeout=timeout)
    return status, (text if status == 200 else None)


def _in_cidr_list(text, addr):
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                cidr = json.loads(line).get("cidr")
            except json.JSONDecodeError:
                continue
        else:
            cidr = line.split()[0]
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return cidr
        except ValueError:
            continue
    return None


def _shared_ip_hint(conn, scope):
    """Wie viele Nutzer typischerweise hinter dieser IP stecken."""
    text = f"{conn.get('isp') or ''} {conn.get('org') or ''}".lower()
    if "cgnat" in scope:
        return "Geteiltes CGNAT-Netz – sehr viele Nutzer", red
    hosting = ("rechenzentr", "datacenter", "data center", "hosting",
               "cloud", "amazon", "google", "meta", "facebook", "akamai",
               "fastly", "gcore", "hetzner", "ovh", "digitalocean", "linode",
               "vultr", "cloudflare", "microsoft", "azure", "leaseweb",
               "contabo", "scaleway", "strato", "ionos", "alibaba", "tencent",
               "softlayer", "selectel", "worldstream", "choopa", "netcup")
    vpn = ("mullvad", "vpn", "proxy", "anonym", "nordvpn", "expressvpn",
           "surfshark", "ivpn", "windscribe", "torproject", "orbitel",
           "ohrschelm", "private internet")
    mobile = ("mobilfunk", "mobile", "telekom", "vodafone", "telefonica",
              "ee limited", "verizon", "t-mobile", "sprint", "orange",
              "sfr", "swisscom", "tele2", "telia", "cellular", "wireless",
              "funk", "lte", "gprs", "umts", "airtel", "bharti", "jio")
    if any(k in text for k in hosting):
        return "Rechenzentrum/Cloud – viele Nutzer hinter dieser IP", yellow
    if any(k in text for k in vpn):
        return "VPN/Proxy – Endnutzer verborgen, viele Nutzer geteilt", yellow
    if any(k in text for k in mobile):
        return "Mobilfunk – IPs werden vergeben und wieder entzogen", yellow
    return "wahrscheinlich einzelner Anschluss (Standort-ISP)", green


def ip_lookup(query=""):
    header("IP-LOOKUP", "Standort, Netz, Routing, Reputation")
    q = (query or "").strip()
    url = "https://ipwho.is/" + (urllib.parse.quote(q) if q else "")

    with Spinner("ipwho.is wird abgefragt"):
        status, data = get_json(url)

    if status == 0 or not data:
        if status == 404:
            print(red("\n   Ungültige IP-Adresse (HTTP 404)."))
        else:
            print(red(f"\n   IP-Service nicht erreichbar (HTTP {status})."))
        return

    # Private/reservierte Bereiche: kein Geo-Ergebnis möglich
    if data.get("success") is False:
        try:
            addr = ipaddress.ip_address(q)
        except ValueError:
            print(red(f"\n   Ungültige IP: {data.get('message', 'fehlerhaft')}"))
            return
        print()
        row("IP", bold(str(addr)))
        row("Bereich", _ip_scope(addr), yellow)
        row("Hinweis", "privat/reserviert – nur im eigenen Netz sichtbar", dim)
        hint("Solche Adressen haben keinen öffentlichen Standort.")
        return

    conn = data.get("connection") or {}
    tz = data.get("timezone") or {}
    flag = data.get("flag") or {}
    try:
        addr = ipaddress.ip_address(str(data.get("ip", "")))
    except ValueError:
        addr = None

    # ------------------------------------------------ Standort
    section("Standort")
    row("IP", bold(data.get("ip")))
    row("Typ", f"{data.get('type')} · "
               f"{_ip_scope(addr) if addr else 'unbekannt'}")
    row("Land", f"{flag.get('emoji', '')} {data.get('country')}"
                f" ({data.get('country_code')})")
    row("Region", data.get("region"))
    row("Stadt", data.get("city"))
    row("PLZ", data.get("postal") or "-")
    row("Koordinaten", f"{data.get('latitude')}, {data.get('longitude')}")
    row("Kontinent", f"{data.get('continent')} "
                     f"({data.get('continent_code')})")
    row("EU-Land", "ja" if data.get("is_eu") else "nein",
        green if data.get("is_eu") else dim)
    row("Hauptstadt", data.get("capital") or "-")
    cc = str(data.get("calling_code") or "")
    iso = str(data.get("country_code") or "")
    if cc:
        row("Telefonvorwahl", f"+{cc} · {_flag(iso)} {iso}  (aus DE: 00{cc})",
            cyan)
        row("Notruf", EMERGENCY.get(iso, "keine Daten hinterlegt"),
            yellow if iso in EMERGENCY else dim)
    else:
        row("Telefonvorwahl", "-")

    offset = tz.get("offset") or 0
    local = datetime.now(timezone.utc) + timedelta(seconds=offset)
    row("Zeitzone", f"{tz.get('id', '-')} ({tz.get('utc', '-')} "
                    f"{tz.get('abbr', '')})")
    row("Ortszeit", local.strftime("%Y-%m-%d %H:%M:%S"))

    # Entfernung zum eigenen Standort (nur bei expliziter Eingabe)
    if q and addr and isinstance(data.get("latitude"), (int, float)):
        with Spinner("eigener Standort wird ermittelt"):
            _, own = get_json("https://ipwho.is/")
        if isinstance(own, dict) and own.get("success") is not False:
            try:
                la1, lo1 = float(own["latitude"]), float(own["longitude"])
                la2, lo2 = float(data["latitude"]), float(data["longitude"])
                km = _haversine(la1, lo1, la2, lo2)
                deg = _bearing(la1, lo1, la2, lo2)
                row("Entfernung",
                    f"{km:,.0f} km {_compass(deg)} von dir "
                    f"({own.get('city', '?')})", cyan)
            except (KeyError, TypeError, ValueError):
                pass

    # ------------------------------------------------ Netz & Routing
    section("Netz & Routing")

    ptr_name, info = None, {}
    if addr:
        with Spinner("Reverse-DNS, ipinfo und RDAP"):
            answers = dns_query(addr.reverse_pointer, "PTR")
            if answers:
                ptr_name = str(answers[0].get("data", "")).rstrip(".")
            s2, info = get_json(f"https://ipinfo.io/{addr}/json", timeout=20)
            if s2 != 200 or not isinstance(info, dict):
                info = {}
            _, rdap_ip = get_json(f"https://rdap.org/ip/{addr}", timeout=25)
            asn_num = conn.get("asn")
            _, rdap_asn = (get_json(f"https://rdap.org/autnum/{asn_num}",
                                    timeout=25) if asn_num else (0, None))

    row("Hostname", ptr_name or info.get("hostname") or "kein PTR-Eintrag",
        green if ptr_name else dim)
    if info.get("anycast") is not None:
        row("Anycast", "ja – gleiche IP überall" if info.get("anycast")
            else "nein", yellow if info.get("anycast") else dim)
    row("ASN", (f"AS{conn.get('asn')} · "
                f"{(rdap_asn or {}).get('name', conn.get('org', '-'))}")
        if conn.get("asn") else "-", green)
    row("ISP", conn.get("isp") or "-")
    row("Organisation", conn.get("org") or "-")

    if isinstance(rdap_ip, dict):
        start = rdap_ip.get("startAddress")
        end = rdap_ip.get("endAddress")
        if start and end and start != end:
            row("Bereich", f"{start} – {end}")
        row("Zuweisung", rdap_ip.get("type") or "-")
        row("RDAP-Name", rdap_ip.get("name") or "-", dim)
        row("Handle", rdap_ip.get("handle") or "-", dim)
        if rdap_ip.get("port43"):
            row("Whois-Server", rdap_ip.get("port43"), dim)

        events = {e.get("eventAction"): e.get("eventDate")
                  for e in (rdap_ip.get("events") or [])}
        if events.get("registration"):
            row("Zugewiesen", str(events["registration"])[:10])
        if events.get("last changed"):
            row("Geändert", str(events["last changed"])[:10])
        row("Registrant", _find_role(rdap_ip.get("entities"), "registrant") or "-",
            dim)
        abuse = _find_abuse(rdap_ip.get("entities"))
        if abuse:
            row("Abuse-Kontakt", abuse, yellow)

    if isinstance(rdap_asn, dict):
        as_events = {e.get("eventAction"): e.get("eventDate")
                     for e in (rdap_asn.get("events") or [])}
        if as_events.get("registration"):
            row("AS registriert", str(as_events["registration"])[:10], dim)

    # ------------------------------------------------ Genauigkeit
    section("Genauigkeit & Betroffene")
    if data.get("city") and data.get("region"):
        accuracy = "Stadt-Ebene · ca. ± 10–25 km"
    elif data.get("region") or data.get("country"):
        accuracy = "Region/Land · ca. ± 50–150 km"
    else:
        accuracy = "keine Ortung möglich"
    row("Ortsgenauigkeit", accuracy, cyan)
    row("Methode", "GeoIP-Datenbank – kein GPS, keine Router-Abfrage", dim)
    shared, shared_color = _shared_ip_hint(
        conn, _ip_scope(addr) if addr else "")
    if info.get("anycast"):
        shared, shared_color = ("Anycast – eine IP über viele Standorte "
                                "weltweit"), yellow
    row("Hinter der IP", shared, shared_color)
    row("Person dahinter", "kann man öffentlich NICHT bestimmen", red)

    # ------------------------------------------------ Reputation
    section("Reputation & Blocklisten")
    if not addr or not addr.is_global:
        row("Prüfung", "entfällt – keine globale Adresse", dim)
    else:
        drop_url = f"https://www.spamhaus.org/drop/drop_v{addr.version}.json"
        with Spinner("Tor, blocklist.de und Spamhaus werden geprüft"):
            tor_status, tor_txt = _text_list(
                "https://check.torproject.org/torbulkexitlist")
            bl_status, bl_txt = _text_list(
                "https://lists.blocklist.de/lists/all.txt")
            drop_status, drop_txt = _text_list(drop_url, timeout=45)

        results = []
        if tor_status == 200 and tor_txt is not None:
            results.append(("Tor-Exit-Node",
                            str(addr) in set(tor_txt.split())))
        else:
            results.append(("Tor-Exit-Node", f"HTTP {tor_status}"))
        if bl_status == 200 and bl_txt is not None:
            results.append(("blocklist.de",
                            str(addr) in set(bl_txt.split())))
        else:
            results.append(("blocklist.de", f"HTTP {bl_status}"))
        if drop_status == 200 and drop_txt is not None:
            hit = _in_cidr_list(drop_txt, addr)
            results.append(("Spamhaus DROP", hit if hit else False))
        else:
            results.append(("Spamhaus DROP", f"HTTP {drop_status}"))

        for label, value in results:
            if value is True:
                row(label, "JA – gelistet", red)
            elif value is False:
                row(label, "nein", green)
            elif isinstance(value, str) and value.startswith("HTTP"):
                note = ("Rate-Limit – später nochmal"
                        if value in ("HTTP 429", "HTTP 403")
                        else f"Prüfung nicht möglich ({value})")
                row(label, note, yellow)
            else:
                row(label, f"JA – gelistet ({value})", red)

        note = ("blocklist.de = als Angreifer gemeldet · "
                "DROP = gekaperte/verschmutzte Bereiche")
        print(f"\n   {dim(note)}")

    print("\n   " + dim("Hinweis: Eine IP-Adresse hat keine eigene "
                        "Telefonnummer – öffentlich"))
    print("   " + dim("existieren nur Vorwahl und Notrufnummern des Landes."))

    section("Was öffentlich existiert")
    print("   " + green("✓ ") + dim(
        "Stadt/PLZ, Betreiber, Netzblock, Hostname, Abuse-Kontakt, Vorwahl"))
    print("   " + red("✗ ") + dim(
        "Straße, Name, E-Mail, Telefon, Profile – das hat nur der Provider"))
    print("   " + dim(
        "Anschluss-Zuordnung = Verkehrsdaten: Auskunft nur an Behörden"))
    print("   " + dim(
        "oder mit Einwilligung. Echter Fall? Dann: Modul 'report' nutzen."))

    hint("Quellen: ipwho.is · ipinfo.io · RDAP · dns.google · "
         "Tor Project · blocklist.de · Spamhaus")


# ---------------------------------------------------------------- 2) DNS
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


def dns_lookup(query):
    header("DNS-LÖSUNG", "DoH über dns.google")
    name = (query or "").strip().lower().replace("https://", "").split("/")[0]
    if not name:
        print(red("\n   Kein Domainname angegeben."))
        return

    with Spinner(f"{name} wird aufgelöst"):
        results = {t: dns_query(name, t) for t in DNS_TYPES}

    print()
    found = False
    for rtype, answers in results.items():
        if not answers:
            continue
        found = True
        values = []
        for a in answers:
            data = str(a.get("data", "")).strip()
            if rtype == "MX":
                parts = data.split()
                if len(parts) >= 2:
                    target = parts[-1].rstrip(".")
                    data = (f"Prio {parts[0]}  {target}" if target
                            else "Null-MX (empfängt keine Mail)")
            elif rtype in ("CNAME", "NS"):
                data = data.rstrip(".")
            if data and data not in values:
                values.append(data)

        print(f"   {cyan(rtype.ljust(6))} {bold(values[0])}")
        for extra in values[1:]:
            print(f"   {'':<6} {dim(extra)}")

    if not found:
        print(yellow("   Keine Einträge gefunden."))
    hint("dns.google (DNS-over-HTTPS) – öffentliche Auflösung")


# ---------------------------------------------------------------- 3) WHOIS
def whois_lookup(query):
    header("WHOIS / RDAP", "Registrierungsdaten einer Domain")
    domain = (query or "").strip().lower()
    domain = domain.replace("https://", "").replace("www.", "").split("/")[0]
    if not domain or "." not in domain:
        print(red("\n   Kein gültiges Domainformat (z.B. example.com)."))
        return

    with Spinner("rdap.org wird abgefragt"):
        status, data = get_json(f"https://rdap.org/domain/{domain}")

    if status == 404:
        print(red(f"\n   Keine RDAP-Daten für {domain} (nicht registriert "
                  f"oder Registry ohne RDAP)."))
        return
    if not isinstance(data, dict):
        print(red(f"\n   RDAP nicht erreichbar (HTTP {status})."))
        return

    events = {e.get("eventAction"): e.get("eventDate")
              for e in (data.get("events") or [])}

    registrar, abuse_email = "-", None
    for ent in data.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = ent.get("handle") or "-"
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn" and item[3]:
                    registrar = item[3]
            for sub in ent.get("entities") or []:
                if "abuse" in (sub.get("roles") or []):
                    vc = sub.get("vcardArray") or [None, []]
                    for item in vc[1]:
                        if item[0] == "email" and item[3]:
                            abuse_email = item[3]

    nameservers = [ns.get("ldhName", "").rstrip(".")
                   for ns in (data.get("nameservers") or [])]

    print()
    row("Domain", bold(domain))
    row("Status", ", ".join(data.get("status") or []) or "-")
    row("Registrar", str(registrar))
    if abuse_email:
        row("Abuse-Kontakt", abuse_email, dim)
    row("Registriert", events.get("registration") or "-")
    row("Läuft ab", events.get("expiration") or "-")
    row("Nameserver", ", ".join(nameservers) or "-", dim)
    hint("RDAP – offizielles WHOIS-Äquivalent, öffentlich")


# ---------------------------------------------------------------- 4) User
def username_check(query):
    header("USERNAME-CHECK", "9 Plattformen, nur öffentliche Profile")
    user = (query or "").strip().lstrip("@")
    if not user:
        print(red("\n   Kein Username angegeben."))
        return

    print(dim(f"\n   Suche nach {bold('@' + user)} ...\n"))
    results = []

    def add(platform, ok, info):
        state = "da" if ok else ("blockiert" if ok is None else "nein")
        results.append((platform, state, info))

    with Spinner("Plattformen werden abgefragt"):
        # GitHub
        s, d = get_json(f"https://api.github.com/users/{urllib.parse.quote(user)}")
        if s == 200 and isinstance(d, dict):
            add("GitHub", True,
                f"{d.get('login')} | {fmt_num(d.get('public_repos'))} Repos | "
                f"{fmt_num(d.get('followers'))} Follower")
        else:
            add("GitHub", None if s in (403, 429) else False,
                "blockiert" if s in (403, 429) else "nicht gefunden")

        # GitLab
        s, d = get_json("https://gitlab.com/api/v4/users?username="
                        + urllib.parse.quote(user))
        if s == 200 and isinstance(d, list):
            if d:
                add("GitLab", True,
                    f"{d[0].get('username')} | "
                    f"{fmt_num(d[0].get('followers_count'))} Follower")
            else:
                add("GitLab", False, "nicht gefunden")
        else:
            add("GitLab", None, f"blockiert (HTTP {s})")

        # Reddit
        s, t = request(f"https://www.reddit.com/user/{urllib.parse.quote(user)}"
                       "/about.json")
        if s == 200:
            try:
                k = json.loads(t)["data"]
                add("Reddit", True,
                    f"karma {fmt_num(k.get('total_karma'))} | seit "
                    f"{time.strftime('%Y-%m-%d', time.gmtime(k.get('created_utc', 0)))}")
            except (json.JSONDecodeError, KeyError, TypeError):
                add("Reddit", True, "gefunden")
        else:
            add("Reddit", None if s in (403, 429) else False,
                "blockiert" if s in (403, 429) else "nicht gefunden")

        # Roblox
        s, d = get_json("https://users.roblox.com/v1/usernames/users",
                        method="POST",
                        data={"usernames": [user], "excludeBannedUsers": False})
        if s == 200 and isinstance(d, dict):
            items = d.get("data") or []
            if items:
                add("Roblox", True,
                    f"{items[0].get('name')} | ID {items[0].get('id')}")
            else:
                add("Roblox", False, "nicht gefunden")
        else:
            add("Roblox", None, f"blockiert (HTTP {s})")

        # Steam
        s, t = request(f"https://steamcommunity.com/id/{urllib.parse.quote(user)}"
                       "?xml=1")
        if s == 200 and "profile not found" not in t.lower() \
                and "could not be found" not in t.lower():
            m = re.search(r"<steamID64>(\d+)</steamID64>", t)
            add("Steam", True,
                f"SteamID64 {m.group(1)}" if m else "gefunden")
        else:
            add("Steam", None if s in (403, 429) else False,
                "blockiert" if s in (403, 429) else "nicht gefunden")

        # HackerNews (liefert 200 auch bei Fehlern – Text prüfen)
        s, t = request(f"https://news.ycombinator.com/user?id="
                       f"{urllib.parse.quote(user)}")
        add("HackerNews", s == 200 and "No such user" not in t,
            "gefunden" if s == 200 and "No such user" not in t
            else "nicht gefunden")

        # Keybase
        s, d = get_json(f"https://keybase.io/{urllib.parse.quote(user)}/api.json")
        add("Keybase", s == 200 and isinstance(d, dict),
            "gefunden" if s == 200 and isinstance(d, dict)
            else "nicht gefunden")

        # TikTok / YouTube
        s, t = request(f"https://www.tiktok.com/@{urllib.parse.quote(user)}")
        if s in (403, 429):
            add("TikTok", None, "blockiert")
        elif s == 200 and '"uniqueId"' in t:
            add("TikTok", True, "Profil vorhanden")
        else:
            add("TikTok", False, "nicht gefunden")

        s, t = request(f"https://www.youtube.com/@{urllib.parse.quote(user)}")
        add("YouTube", s == 200 and len(t) > 5000,
            "Kanal vorhanden" if s == 200 and len(t) > 5000
            else "nicht gefunden")

    icons = {"da": green("[+]"), "nein": dim("[-]"),
             "blockiert": yellow("[?]")}
    for platform, state, info in results:
        print(f"   {icons.get(state, '   ')} {bold(platform.ljust(11))} "
              f"{dim(info)}")

    hits = sum(1 for _, st, _ in results if st == "da")
    blocked = sum(1 for _, st, _ in results if st == "blockiert")
    print(f"\n   {bold(str(hits))} Treffer von {len(results)} Plattformen"
          + (f"  {dim(f'({blocked} blockiert)')}" if blocked else ""))
    hint("[+] vorhanden  [-] nicht gefunden  [?] geblockt (kein Ergebnis)")


# ---------------------------------------------------------------- 5) Mail
MX_HINTS = [
    ("google.com", "Google – Gmail / Workspace"),
    ("googlemail.com", "Google – Gmail"),
    ("outlook.com", "Microsoft 365"),
    ("office365.com", "Microsoft 365"),
    ("protonmail", "Proton Mail"),
    ("proton.me", "Proton Mail"),
    ("ionos.", "IONOS"),
    ("gmx.", "GMX / Mail.com"),
    ("mail.com", "GMX / Mail.com"),
    ("web.de", "GMX / Mail.com"),
    ("t-online.de", "T-Online (Telekom)"),
    ("yahoo.", "Yahoo Mail"),
    ("zoho.", "Zoho Mail"),
    ("fastmail.", "Fastmail"),
    ("amazonaws.com", "Amazon SES"),
    ("sendgrid.net", "SendGrid"),
    ("mcsv.net", "Mailchimp"),
    ("hubspot", "HubSpot"),
    ("secureserver.net", "GoDaddy"),
    ("strato.", "Strato"),
    ("hetzner.", "Hetzner"),
    ("ovh.", "OVH"),
    ("hosteurope", "Host Europe"),
    ("united-domains", "united-domains"),
    ("mailbox.org", "Mailbox.org"),
    ("posteo.de", "Posteo"),
]


def _mx_provider(hosts):
    joined = " ".join(hosts).lower()
    for needle, label in MX_HINTS:
        if needle in joined:
            return label
    return "eigene / unbekannte Infrastruktur"


def _txt_records(data):
    return [str(a.get("data", "")).strip('"')
            for a in ((data or {}).get("Answer") or [])]


def email_triage(query):
    header("E-MAIL-TRIAGE", "Provider, Mail-Security, Profil")
    mail = (query or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", mail):
        print(red("\n   Syntax ungültig (z.B. name@domain.de)."))
        return
    domain = mail.split("@", 1)[1]

    with Spinner("MX, SPF, DMARC, BIMI, MTA-STS, DNSSEC, RDAP"):
        _, mx_data = get_json(f"https://dns.google/resolve?name={domain}&type=MX")
        _, txt_data = get_json(f"https://dns.google/resolve?name={domain}&type=TXT")
        _, dmarc_data = get_json(
            f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT")
        _, bimi_data = get_json(
            f"https://dns.google/resolve?name=default._domainkey.{domain}&type=TXT")
        _, sts_data = get_json(
            f"https://dns.google/resolve?name=_mta-sts.{domain}&type=TXT")
        _, rpt_data = get_json(
            f"https://dns.google/resolve?name=_smtp._tls.{domain}&type=TXT")
        _, ds_data = get_json(f"https://dns.google/resolve?name={domain}&type=DS")
        _, a_data = get_json(f"https://dns.google/resolve?name={domain}&type=A")
        _, rdap = get_json(f"https://rdap.org/domain/{domain}", timeout=25)

    mx = [str(a.get("data", "")) for a in ((mx_data or {}).get("Answer") or [])]
    mx_targets = [m.split()[-1].rstrip(".") for m in mx if len(m.split()) > 1]
    null_mx = bool(mx_targets) and all(t == "" for t in mx_targets)
    txts = _txt_records(txt_data)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in _txt_records(dmarc_data)
                  if "v=dmarc1" in t.lower()), None)
    bimi = next((t for t in _txt_records(bimi_data)
                 if "v=bimi1" in t.lower()), None)
    sts = next((t for t in _txt_records(sts_data)
                if "v=mta-sts" in t.lower()), None)
    rpt = next((t for t in _txt_records(rpt_data)
                if "v=smtp-tlsrpt" in t.lower()), None)
    dnssec = bool((ds_data or {}).get("Answer"))
    a_records = [a.get("data") for a in ((a_data or {}).get("Answer") or [])
                 if a.get("type") == 1]

    # ------------------------------------------------ Absender & Domain
    section("Absender & Domain")
    row("Adresse", bold(mail))
    row("Domain", domain)
    if not mx:
        row("MX-Server", "KEINE (kann keine Mail empfangen)", red)
    elif null_mx:
        row("MX-Server", "Null-MX (empfängt keine Mail)", yellow)
    elif mx_targets:
        row("MX-Server", mx_targets[0], green)
    else:
        row("MX-Server", f"unklar ({mx[0]})", dim)
    if mx_targets and not null_mx:
        row("Mail-Anbieter", _mx_provider(mx_targets), green)
    row("Website", a_records[0] if a_records else "kein A-Record", dim)

    if isinstance(rdap, dict):
        events = {e.get("eventAction"): e.get("eventDate")
                  for e in (rdap.get("events") or [])}
        reg = events.get("registration")
        if reg:
            try:
                reg_dt = datetime.fromisoformat(str(reg).replace("Z", "+00:00"))
                years = (datetime.now(timezone.utc) - reg_dt).days / 365.25
                row("Domainalter", f"{years:.1f} Jahre (seit {reg[:10]})")
            except ValueError:
                pass
        expires = str(events.get("expiration") or "")[:10]
        if expires:
            expired = expires < datetime.now(timezone.utc).strftime("%Y-%m-%d")
            row("Läuft ab", expires + ("  (abgelaufen!)" if expired else ""),
                red if expired else bold)

    # ------------------------------------------------ Mail-Security
    section("Mail-Security")
    if spf:
        tokens = spf.split()
        allm = next((t for t in tokens if t in ("-all", "~all", "+all", "?all")),
                    None)
        includes = sum(1 for t in tokens if t.startswith("include:"))
        policy_map = {
            "-all": "-all (streng)",
            "~all": "~all (weich)",
            "+all": "+all (ALLES erlaubt!)",
            "?all": "?all (unsicher)",
        }
        policy = policy_map.get(allm, "kein All-Mechanismus")
        color = red if allm in ("+all", None) else (
            green if allm == "-all" else yellow)
        row("SPF", f"{policy} · {includes} include(s)", color)
    else:
        row("SPF", "fehlt – Absenderfälschung möglich", red)

    if dmarc:
        tags = {}
        for kv in dmarc.split(";"):
            if "=" in kv:
                key, value = kv.split("=", 1)
                tags[key.strip().lower()] = value.strip()
        policy = tags.get("p", "?")
        color = green if policy == "reject" else (
            yellow if policy == "quarantine" else red)
        detail = f"p={policy}"
        if "sp" in tags:
            detail += f", sp={tags['sp']}"
        detail += f", pct={tags.get('pct', '100')}"
        row("DMARC", detail, color)
        row("DMARC-Reports", tags.get("rua") or tags.get("ruf") or "keine", dim)
    else:
        row("DMARC", "fehlt – Spoofing-Schutz aus", red)

    mode = re.search(r"mode=([a-z]+)", sts or "")
    row("MTA-STS", (f"mode={mode.group(1)}" if mode
                    else ("vorhanden" if sts else "fehlt")),
        green if mode and mode.group(1) == "enforce" else
        (yellow if sts else dim))
    row("TLS-RPT", "vorhanden" if rpt else "fehlt",
        green if rpt else dim)
    row("BIMI", "vorhanden (Absender-Logo)" if bimi else "fehlt",
        green if bimi else dim)
    row("DNSSEC", "Domain signiert (DS)" if dnssec else "nicht signiert",
        green if dnssec else dim)

    # ------------------------------------------------ Öffentliches Profil
    section("Öffentliches Profil")
    avatar_hash = hashlib.md5(mail.encode("utf-8")).hexdigest()
    with Spinner("Gravatar wird geprüft"):
        s_avatar, _ = request(f"https://www.gravatar.com/avatar/{avatar_hash}"
                              "?d=404&size=64")
        s_prof, prof_txt = request(f"https://gravatar.com/{avatar_hash}.json")

    entry = None
    if s_prof == 200:
        try:
            entry = (json.loads(prof_txt).get("entry") or [None])[0]
        except (json.JSONDecodeError, AttributeError):
            entry = None

    row("Gravatar-Avatar", "vorhanden" if s_avatar == 200 else "nein",
        yellow if s_avatar == 200 else dim)
    if entry:
        row("Profilname", entry.get("displayName")
            or entry.get("preferredUsername") or "-", green)
        row("Benutzername", entry.get("preferredUsername") or "-", dim)
        row("Standort", entry.get("location") or "-", dim)
        if entry.get("profileUrl"):
            row("Profil-URL", entry.get("profileUrl"), dim)
        accounts = entry.get("accounts") or []
        if accounts:
            linked = ", ".join(str(a.get("shortname") or a.get("url") or "")
                               for a in accounts[:6])
            row("Verknüpft mit", linked, yellow)
        photos = entry.get("photos") or []
        if photos and photos[0].get("value"):
            row("Avatar-URL", photos[0]["value"], dim)
    else:
        row("Profil", "kein öffentliches Gravatar-Profil", dim)

    # ------------------------------------------------ optionale Breach-API
    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key:
        s, txt = request(
            "https://haveibeenpwned.com/api/v3/breachedaccount/" + mail,
            headers={"hibp-api-key": hibp_key, "user-agent": UA})
        if s == 200:
            try:
                breaches = json.loads(txt)
                names = ", ".join(b.get("Name", "?")
                                  for b in breaches[:5])
                row("Breach-Status", f"{len(breaches)} Datenabflüsse: {names}",
                    red)
            except json.JSONDecodeError:
                row("Breach-Status", "Antwort nicht lesbar", yellow)
        elif s == 404:
            row("Breach-Status", "kein Eintrag bei HIBP", green)
        else:
            row("Breach-Status", f"HTTP {s}", yellow)

    # ------------------------------------------------ Grenzen
    section("Nicht öffentlich")
    print(f"   {dim('Geräte, Standort, Postfachinhalt und Anmeldehistorie dieser')}")
    print(f"   {dim('Adresse sieht nur der Mail-Anbieter. Geräteliste z.B. bei')}")
    print(f"   {dim('Google: myaccount.google.com/security → Geräte.')}")
    hint("Geprüft wurden ausschließlich öffentliche DNS-Einträge – "
         "keine Mail gesendet, nichts angemeldet.")


# ---------------------------------------------------------------- 5b) Telefon
SHORT_NUMBERS = {
    "110": "Polizei (DE)", "112": "Feuerwehr / Rettung (EU)", 
    "115": "Behördennummer (DE)", "116117": "Ärztebereitschaft (DE)",
    "116118": "Zahnärztebereitschaft (DE)", "116119": "Psychosoziale Beratung",
    "11833": "Auskunft (DE, gebührenpflichtig)",
    "11880": "Auskunft (DE, teuer)", "911": "Notruf (US/CA)",
    "999": "Notruf (UK)", "000": "Notruf (AU)", "111": "Notruf (UK/NZ)",
    "119": "Feuerwehr/Rettung (JP)", "120": "Sanitätsnotdienst (JP)",
    "122": "Polizei (AT)", "144": "Rettung (AT)", "145": "Giftnotruf (AT)",
    "1414": "Notruf (CH)", "117": "Rettung (CH)", "118": "Feuerwehr (CH)",
    "133": "Polizei (AT)", "141": "Giftnotruf (CH)", "19": "Polizei (FR)",
    "18": "Feuerwehr (FR)", "15": "Sanitätsnotdienst (FR)",
    "113": "Polizei (NL)", "10111": "Polizei (ZA)", "1122": "Notruf (PK)",
    "10115": "Stadtservice (BR)", "1911": "Notruf (NZ)", "1131": "Polizei (TW)",
}

PN_TYPES = {}
if pn:
    PN_TYPES = {
        pn.PhoneNumberType.FIXED_LINE: "Festnetz",
        pn.PhoneNumberType.MOBILE: "Mobilfunk",
        pn.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Festnetz oder Mobil",
        pn.PhoneNumberType.TOLL_FREE: "Gebührenfrei",
        pn.PhoneNumberType.PREMIUM_RATE: "Mehrwertnummer (Premium)",
        pn.PhoneNumberType.SHARED_COST: "Shared-Cost-Nummer",
        pn.PhoneNumberType.VOIP: "VoIP",
        pn.PhoneNumberType.PERSONAL_NUMBER: "Persönliche Rufweitenummer",
        pn.PhoneNumberType.PAGER: "Pager",
        pn.PhoneNumberType.UAN: "Unternehmensnummer (UAN)",
        pn.PhoneNumberType.VOICEMAIL: "Voicemail",
        pn.PhoneNumberType.UNKNOWN: "nicht bestimmbar",
    }


def _flag(iso2):
    if not iso2 or len(iso2) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in iso2.upper())


def phone_lookup(query):
    header("TELEFONNUMMER", "Format, Land, Typ, Zeitzone")
    raw = (query or "").strip()
    if not raw:
        print(red("\n   Keine Nummer (z.B. +49 170 1234567 oder 0170 1234567)."))
        return

    digits = re.sub(r"\D", "", raw)
    if not digits:
        print(red("\n   Keine Ziffern in der Eingabe (z.B. +49 170 1234567)."))
        return

    # Kurz-/Notrufnummern
    if not raw.startswith("+") and len(digits) <= 5:
        print()
        row("Eingabe", bold(raw))
        if digits in SHORT_NUMBERS:
            row("Kurznummer", digits, yellow)
            row("Bedeutung", SHORT_NUMBERS[digits], green)
            row("Typ", "Kurz- / Notrufnummer", yellow)
        else:
            row("Nummer", digits, dim)
            row("Typ", "Kurznummer – keine Bedeutung hinterlegt", yellow)
        hint("Kurznummern sind länderspezifisch (hier: überwiegend DE/EU).")
        return

    if pn is None:
        print(yellow("\n   'phonenumbers' ist nicht installiert – "
                     "nur Basisanalyse möglich."))
        print(dim("   Installation:  pip install phonenumbers\n"))
        row("Eingabe", bold(raw))
        row("Ziffern", digits)
        return

    # Ohne "+" wird die Nummer als deutsche Nummer interpretiert
    assume_de = not raw.lstrip().startswith("+")
    try:
        number = pn.parse(raw, "DE" if assume_de else None)
    except Exception as e:                                  # noqa: BLE001
        print(red(f"\n   Nummer nicht lesbar: {e}"))
        return

    region = pn.region_code_for_country_code(number.country_code) or ""
    valid = pn.is_valid_number(number)
    possible = pn.is_possible_number(number)
    type_name = PN_TYPES.get(pn.number_type(number), "nicht bestimmbar")
    location = pn_geo.description_for_number(number, "de")
    country = pn_geo.country_name_for_number(number, "de")
    carrier_name = pn_carrier.name_for_number(number, "de")
    tz_names = pn_tz.time_zones_for_number(number)
    tz_name = None
    for candidate in tz_names:
        if candidate and candidate != "Etc/Unknown":
            tz_name = candidate
            break

    # ------------------------------------------------ Nummer
    section("Nummer")
    row("Eingabe", bold(raw))
    if assume_de:
        row("Annahme", "ohne '+' als deutsche Nummer gelesen", dim)
    row("Länderrufnummer", f"+{number.country_code}  {_flag(region)} {country}")
    row("E.164", pn.format_number(number, pn.PhoneNumberFormat.E164), green)
    row("National", pn.format_number(number, pn.PhoneNumberFormat.NATIONAL))
    row("International",
        pn.format_number(number, pn.PhoneNumberFormat.INTERNATIONAL))
    row("RFC3966", pn.format_number(number, pn.PhoneNumberFormat.RFC3966), dim)

    # ------------------------------------------------ Einordnung
    section("Einordnung")
    if valid:
        row("Gültigkeit", "gültig", green)
    elif possible:
        row("Gültigkeit", "Format möglich, Nummer aber ungültig", yellow)
    else:
        row("Gültigkeit", "ungültig", red)

    # Deutsche Sonderrufnummern anhand der Nationalnummer nachziehen
    if type_name == "nicht bestimmbar" and assume_de:
        nat_digits = re.sub(
            r"\D", "",
            pn.format_number(number, pn.PhoneNumberFormat.NATIONAL))
        if nat_digits.startswith("0900"):
            type_name = "Mehrwertnummer (Premium)"
        elif nat_digits.startswith("018"):
            type_name = "Mehrwertdienst (018x)"
        elif nat_digits.startswith("0800"):
            type_name = "Gebührenfrei (0800)"

    row("Typ", type_name,
        red if (pn.number_type(number) == pn.PhoneNumberType.PREMIUM_RATE
                or "Mehrwert" in type_name)
        else (green if type_name == "Mobilfunk" else bold))
    if location:
        row("Ort/Region", location)
    if carrier_name:
        row("Anbieter", carrier_name, green)
    else:
        row("Anbieter", "in den Metadaten nicht hinterlegt", dim)
    if tz_name:
        row("Zeitzone", tz_name)
        if ZoneInfo:
            try:
                local = datetime.now(ZoneInfo(tz_name))
                row("Ortszeit dort", local.strftime("%Y-%m-%d %H:%M %Z"), cyan)
            except Exception:                               # noqa: BLE001
                pass
    example = pn.example_number(region) if region else None
    if example:
        row("Beispiel-Nr.",
            pn.format_number(example, pn.PhoneNumberFormat.INTERNATIONAL), dim)

    # ------------------------------------------------ Wählen
    section("Wählen")
    for iso, label in (("DE", "Aus Deutschland"), ("US", "Aus den USA"),
                       ("GB", "Aus GB")):
        try:
            dial = pn.format_out_of_country_calling_number(number, iso)
            row(label, dial)
        except Exception:                                   # noqa: BLE001
            pass

    hint("Nur libphonenumber-Metadaten (offline). Name, Inhaber und "
         "Standort einer Rufnummer sind nicht öffentlich einsehbar.")



# ---------------------------------------------------------------- 6) Archiv
def archive_check(query):
    header("WAYBACK-ARCHIV", "ältere Zustände einer URL")
    url = (query or "").strip()
    if not url:
        print(red("\n   Keine URL angegeben."))
        return
    if not url.startswith("http"):
        url = "https://" + url

    with Spinner("archive.org wird abgefragt"):
        status, data = get_json(
            "https://archive.org/wayback/available?url="
            + urllib.parse.quote(url))
    closest = ((data or {}).get("archived_snapshots") or {}).get("closest")

    if not closest:
        print(yellow(f"\n   Kein Snapshot für {url} gefunden."))
        print()
        return

    stamp = str(closest.get("timestamp", ""))
    pretty = (f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]} "
              f"{stamp[8:10]}:{stamp[10:12]}" if len(stamp) >= 12 else stamp)

    print()
    row("URL", url, dim)
    row("Snapshot", closest.get("url"), green)
    row("Zeitstempel", pretty)
    row("Status", closest.get("status"))
    hint("Wayback Machine (archive.org) – öffentlich")


# ---------------------------------------------------------------- 7) Subnet
def subnet_calc(query):
    header("SUBNETZ-RECHNER", "CIDR-Berechnung, komplett lokal")
    q = (query or "").strip()
    if not q:
        print(red("\n   Eingabe z.B. 192.168.1.130/24 oder 10.0.0.5"))
        return
    if "/" not in q:
        q += "/32"

    try:
        net = ipaddress.ip_network(q, strict=False)
    except ValueError as e:
        print(red(f"\n   Ungültig: {e}"))
        return

    hosts = net.num_addresses if net.version == 6 or net.prefixlen >= 31 \
        else max(net.num_addresses - 2, 0)

    print()
    row("Netzwerk", bold(str(net)))
    row("Netzadresse", str(net.network_address), green)
    row("Broadcast", str(net.broadcast_address) if net.version == 4 else "-")
    row("Maske", str(net.netmask))
    row("Wildcard", str(net.hostmask))
    row("Präfix", f"/{net.prefixlen}")
    row("Adressen", fmt_num(net.num_addresses))
    row("Hosts", fmt_num(hosts))
    if net.version == 4 and net.prefixlen < 31:
        first = net.network_address + 1
        last = net.broadcast_address - 1
        row("Erster Host", str(first))
        row("Letzter Host", str(last))

        o = int(str(net.network_address).split(".")[0])
        if o == 127:
            klasse = "Loopback (127.0.0.0/8)"
        elif o < 128:
            klasse = "Klasse A (1 – 126)"
        elif o < 192:
            klasse = "Klasse B (128 – 191)"
        elif o < 224:
            klasse = "Klasse C (192 – 223)"
        elif o < 240:
            klasse = "Klasse D (Multicast)"
        else:
            klasse = "Klasse E (reserviert)"
        row("Klasse", klasse, dim)

    scope = ("privat/lokal" if net.is_private else "öffentlich")
    if net.is_loopback:
        scope = "Loopback"
    elif net.is_link_local:
        scope = "Link-Local"
    row("Gültigkeit", scope, yellow if net.is_private else green)
    hint("Berechnet mit Python-Modul ipaddress – nichts gesendet")


# ---------------------------------------------------------------- 8) Hash
HASH_NAMES = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
              96: "SHA-384", 128: "SHA-512"}


def hash_tool(query):
    header("HASH-WERKZEUG", "erkennen oder erzeugen (lokal)")
    text = query or ""
    if not text:
        print(red("\n   Eingabe fehlt – z.B. 'hallo' oder eine MD5-Zeichenkette."))
        return

    force = text.startswith("hash:")
    if force:
        text = text[5:].lstrip()

    looks_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", text))
    detected = HASH_NAMES.get(len(text)) if (looks_hex and not force) else None

    print()
    if detected:
        row("Erkannt", bold(f"{detected} ({len(text)} Hex-Zeichen)"), green)
        row("Hash", text, dim)
        print(f"\n   {dim('Zum Erzeugen eines Hashes die Eingabe mit ')}"
              f"{bold('hash:')}{dim(' voranstellen.')}")
        return

    data = text.encode("utf-8")
    row("Eingabe", text, dim)
    row("Bytes", f"{len(data)}")
    print()
    for name, fn in (("MD5", hashlib.md5), ("SHA-1", hashlib.sha1),
                     ("SHA-256", hashlib.sha256), ("SHA-512", hashlib.sha512),
                     ("SHA3-256", hashlib.sha3_256),
                     ("BLAKE2b-256", lambda b: hashlib.blake2b(b, digest_size=32))):
        row(name, fn(data).hexdigest(), bold)
    hint("Alles lokal berechnet – die Eingabe verlässt deinen Rechner nicht")


# ---------------------------------------------------------------- 9) Passwort
COMMON = {
    "password", "123456", "123456789", "12345678", "qwerty", "letmein",
    "iloveyou", "admin", "monkey", "dragon", "sunshine", "football",
    "abc123", "password1", "111111", "welcome", "princess", "starwars",
    "passw0rd", "superman", "shadow", "master", "hello", "freedom",
    "trustno1", "login", "welcome1", "qazwsx", "654321", "000000",
}


def password_check(query):
    header("PASSWORT-STÄRKE", "komplett lokal – nichts wird gesendet")
    pw = query or ""
    if not pw:
        print(red("\n   Kein Passwort eingegeben."))
        return

    classes = []
    if re.search(r"[a-z]", pw):
        classes.append(("Kleinbuchstaben", 26))
    if re.search(r"[A-Z]", pw):
        classes.append(("Großbuchstaben", 26))
    if re.search(r"\d", pw):
        classes.append(("Ziffern", 10))
    if re.search(r"[^\w\s]|[ _\-.]", pw):
        classes.append(("Sonder-/Trennzeichen", 33))

    charset = sum(c for _, c in classes) or 1
    bits = len(pw) * math.log2(charset)

    problems = []
    if pw.lower() in COMMON:
        problems.append("in gängigen Passwort-Listen")
    if re.search(r"(.)\1{2,}", pw):
        problems.append("mehrfach wiederholte Zeichen")
    if re.search(r"(?:0123456789|abcdefghijklmnopqrstuvwxyz|qwerty|asdfgh)",
                 pw.lower()):
        problems.append("Tastatur- oder Zahlenfolge")
    if re.fullmatch(r"\d{4,}", pw):
        problems.append("nur Ziffern")
    if len(pw) < 8:
        problems.append("kürzer als 8 Zeichen")

    if problems and pw.lower() in COMMON:
        bits = min(bits, 20)

    if bits < 28:
        rating, color = "sehr schwach", red
    elif bits < 36:
        rating, color = "schwach", red
    elif bits < 60:
        rating, color = "mittel", yellow
    elif bits < 80:
        rating, color = "stark", green
    else:
        rating, color = "sehr stark", green

    guesses = 2 ** max(bits - 1, 0)
    offline = fmt_duration(guesses / 1e10)
    online = fmt_duration(guesses / 100)

    print()
    row("Länge", f"{len(pw)} Zeichen")
    row("Zeichensatz", ", ".join(n for n, _ in classes) or "-")
    row("Zeichenpool", fmt_num(charset))
    row("Entropie", f"{bits:.0f} Bit", color)
    print(f"   {dim('Bewertung'.ljust(LABEL_W))} {color(bold(rating))}")

    filled = int(min(bits / 128, 1) * 30)
    print(f"\n   {color('█' * filled)}{dim('░' * (30 - filled))}"
          f"  {color(bold(f'{bits:.0f} Bit'))} {dim('/ 128')}")

    def approx(text):
        return text if text[:1] in ("<≈~") else "~" + text

    print()
    row("Raten offline", f"{approx(offline)} {dim('(10 Mrd. Versuche/s)')}")
    row("Raten online", f"{approx(online)} {dim('(100 Versuche/s)')}")

    if problems:
        print()
        for p in problems:
            print(f"   {yellow('!')} {p}")
    hint("Bewertung rein lokal berechnet – das Passwort wurde NICHT übertragen")


# ---------------------------------------------------------------- 10) MAC
def mac_vendor(query):
    header("MAC-VENDOR", "OUI-Abfrage des Herstellers")
    mac = (query or "").strip()
    if not re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", mac):
        print(red("\n   Ungültiges Format (z.B. 00:1A:2B:3C:4D:5E)."))
        return

    with Spinner("api.macvendors.com"):
        status, text = request(
            "https://api.macvendors.com/" + urllib.parse.quote(mac))

    print()
    row("MAC", bold(mac.upper()))
    row("OUI", mac.upper().replace(":", "").replace("-", "")[:6])
    if status == 200 and text.strip():
        row("Hersteller", text.strip(), green)
    elif status == 404:
        row("Hersteller", "kein Eintrag gefunden", dim)
    elif status == 429:
        row("Hersteller", "Rate-Limit erreicht (später nochmal)", yellow)
    else:
        row("Hersteller", f"abfrage fehlgeschlagen (HTTP {status})", red)
    hint("api.macvendors.com – öffentliche OUI-Datenbank")


# ---------------------------------------------------------------- 11) Redirect
class _ChainHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append((code, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def redirect_check(query):
    header("URL-REDIRECT-KETTE", "Entkürzung und Weiterleitungen auflösen")
    url = (query or "").strip()
    if not url:
        print(red("\n   Keine URL angegeben."))
        return
    if not url.startswith("http"):
        url = "https://" + url

    handler = _ChainHandler()
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    status, final_url, err = None, url, None

    with Spinner("Kette wird aufgelöst"):
        try:
            resp = opener.open(req, timeout=20)
            status = resp.status
            final_url = resp.geturl()
            resp.close()
        except urllib.error.HTTPError as e:
            status, final_url, err = e.code, e.geturl(), str(e)
        except Exception as e:
            err = str(e)

    if err and status is None:
        print(red(f"\n   Fehler: {err}"))
        return

    print()
    row("Start", url, dim)
    if not handler.chain:
        row("Weiterleitungen", "keine – URL ist direkt", yellow)
    else:
        row("Sprünge", len(handler.chain))
        print()
        for i, (code, target) in enumerate(handler.chain, 1):
            color = green if code in (301, 302, 303, 307, 308) else yellow
            print(f"   {dim(f'{i:>2}.')} {color(f'{code}')} → {target}")
    print()
    row("Ziel", final_url, green)
    row("Status", status)
    hint("Nur Weiterleitungen verfolgt – Seite wurde nicht ausgeführt")


# ---------------------------------------------------------------- 12) Header
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


SEC_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking-Schutz"),
    ("X-Content-Type-Options", "MIME-Sniffing-Schutz"),
    ("Referrer-Policy", "Referrer-Steuerung"),
    ("Permissions-Policy", "Feature-Steuerung"),
    ("Cross-Origin-Opener-Policy", "COOP"),
]


def headers_check(query):
    header("HTTP-HEADER", "Security-Konfiguration einer URL")
    url = (query or "").strip()
    if not url:
        print(red("\n   Keine URL angegeben."))
        return
    if not url.startswith("http"):
        url = "https://" + url

    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="HEAD")

    with Spinner("Header werden geladen"):
        try:
            resp = opener.open(req, timeout=20)
            status, hdrs = resp.status, resp.headers
            resp.close()
        except urllib.error.HTTPError as e:
            status, hdrs = e.code, e.headers
        except Exception as e:
            print(red(f"\n   Fehler: {e}"))
            return

    if status in (405, 501):
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        try:
            resp = opener.open(req, timeout=20)
            status, hdrs = resp.status, resp.headers
            resp.close()
        except urllib.error.HTTPError as e:
            status, hdrs = e.code, e.headers
        except Exception as e:
            print(red(f"\n   Fehler: {e}"))
            return

    def h(name):
        return hdrs.get(name)

    print()
    row("URL", url, dim)
    row("Status", str(status), green if status == 200 else yellow)
    row("Server", h("Server") or "-")
    row("Powered-By", h("X-Powered-By") or dim("-"))
    row("Content-Type", h("Content-Type") or "-")
    row("Via/Cache", h("Via") or h("X-Cache") or "-")

    section("Security-Header")
    score = 0
    for header_name, label in SEC_HEADERS:
        value = h(header_name)
        if value:
            score += 1
            print(f"   {green('✓')} {bold(header_name.ljust(28))} {dim(label)}")
            for value_line in textwrap.wrap(str(value), 86) or [""]:
                print(f"     {dim(value_line)}")
        else:
            print(f"   {red('✗')} {dim(header_name.ljust(28))} {label}")

    cookies = []
    try:
        cookies = hdrs.get_all("Set-Cookie") or []
    except AttributeError:
        c = hdrs.get("Set-Cookie")
        cookies = [c] if c else []

    section("Cookies")
    if not cookies:
        print(f"   {dim('- keine gesetzt')}")
    for ck in cookies:
        name = ck.split("=")[0].strip()
        flags = [f for f, on in (("Secure", "secure" in ck.lower()),
                                 ("HttpOnly", "httponly" in ck.lower()),
                                 ("SameSite", "samesite" in ck.lower())) if on]
        print(f"   {green('•')} {name.ljust(24)} {dim(', '.join(flags) or 'keine Flags')}")

    total = len(SEC_HEADERS) + 3
    print(f"\n   {dim('Bewertung'.ljust(LABEL_W))} "
          f"{green(str(score))} von {len(SEC_HEADERS)} Security-Headern")
    hint("Nur Header gelesen – keine Anfrage ausgeführt, nichts verändert")


# ---------------------------------------------------------------- 13) PTR
def ptr_lookup(query):
    header("REVERSE-DNS (PTR)", "IP → Hostname")
    ip = (query or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        print(red("\n   Keine gültige IP-Adresse."))
        return

    with Spinner(f"PTR für {ip}"):
        answers = dns_query(addr.reverse_pointer, "PTR")

    print()
    row("IP", bold(str(addr)))
    row("Abfrage", addr.reverse_pointer, dim)
    names = [str(a.get("data", "")).rstrip(".") for a in (answers or [])]
    if names:
        row("Hostname", names[0], green)
        for extra in names[1:]:
            row("", dim(extra))
    else:
        row("Hostname", "kein PTR-Eintrag", yellow)
    hint("dns.google – öffentliche Auflösung, PTR-Einträge sind freiwillig")


# ---------------------------------------------------------------- 14) CVE
def cve_search(query):
    header("CVE-SUCHE", "Schwachstellen-Datenbank NVD")
    keyword = (query or "").strip()
    if not keyword:
        print(red("\n   Suchbegriff fehlt (z.B. log4j, openssl, vpn)."))
        return

    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"
           f"&keywordSearch={urllib.parse.quote(keyword)}")
    with Spinner("NVD wird durchsucht (kann kurz dauern)"):
        status, data = get_json(url, timeout=40)

    if status == 403 or status == 429:
        print(yellow("\n   NVD limitiert Anfragen – in 30 Sekunden nochmal."))
        return
    if not isinstance(data, dict):
        print(red(f"\n   NVD nicht erreichbar (HTTP {status})."))
        return

    vulns = data.get("vulnerabilities") or []
    print(f"\n   {dim(str(data.get('totalResults', len(vulns))) + ' Treffer gesamt')}")
    if not vulns:
        print(yellow("   Keine CVEs gefunden.\n"))
        return

    for entry in vulns:
        cve = entry.get("cve") or {}
        vid = cve.get("id", "?")
        published = str(cve.get("published", ""))[:10]
        desc = "-"
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = d.get("value", "-")
                break

        score, severity = None, None
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            block = metrics.get(key)
            if block:
                data_v = (block[0] or {}).get("cvssData") or {}
                score = data_v.get("baseScore")
                severity = (block[0] or {}).get("baseSeverity") \
                    or data_v.get("baseSeverity")
                break

        color = green
        if score is not None:
            color = red if score >= 9 else (yellow if score >= 7 else green)

        print()
        print(f"   {bold(magenta(vid))}  {dim(published)}  "
              + (color(bold(f"CVSS {score} ({severity})")) if score
                 else dim("kein Score")))
        for desc_line in textwrap.wrap(desc, 88) or ["-"]:
            print(f"     {dim(desc_line)}")
        print(f"   {cyan('  https://nvd.nist.gov/vuln/detail/' + vid)}")

    hint("Quelle: NIST NVD – bis zu 5 Ergebnisse pro Suche")


# ---------------------------------------------------------- 15) Abuse-Report
def abuse_report(query):
    header("ABUSE-REPORT", "Fertige Meldung an den Provider")
    ip = (query or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        print(red("\n   Keine gültige IP-Adresse (z.B. 203.0.113.44)."))
        return

    with Spinner("Netz, Abuse-Kontakt und Zeitstempel sammeln"):
        _, who = get_json(f"https://ipwho.is/{ip}")
        _, rdap_ip = get_json(f"https://rdap.org/ip/{ip}", timeout=25)
        answers = dns_query(addr.reverse_pointer, "PTR")
        _, own = get_json("https://ipwho.is/")

    conn = (who or {}).get("connection") or {}
    isp = conn.get("isp") or conn.get("org") or "unbekannt"
    asn = conn.get("asn")
    ptr = (str((answers or [{}])[0].get("data", "")).rstrip(".")
           if answers else "-")
    rdap_ok = isinstance(rdap_ip, dict)
    abuse_mail = _find_abuse(rdap_ip.get("entities")) if rdap_ok else None
    start = rdap_ip.get("startAddress") if rdap_ok else None
    end = rdap_ip.get("endAddress") if rdap_ok else None
    whois_server = rdap_ip.get("port43") if rdap_ok else None
    own_ip = (own or {}).get("ip") or "-"
    now = datetime.now(timezone.utc)

    section("Ziel der Meldung")
    row("Empfänger", abuse_mail or "nicht in RDAP – Whois nutzen",
        green if abuse_mail else yellow)
    row("Betreiber", isp)
    row("Netzblock", f"{start} – {end}" if start and end else "-")
    row("ASN", f"AS{asn}" if asn else "-")
    row("Deine IP", own_ip, cyan)
    row("Zeitstempel", now.strftime("%Y-%m-%d %H:%M:%S UTC"))
    if not abuse_mail:
        row("Whois-Server", whois_server or "unbekannt", dim)
        row("Suche selbst", f"https://rdap.org/ip/{ip}", dim)

    date_short = now.strftime("%Y-%m-%d")
    section("Vorlage (kopieren & [Platzhalter] ausfüllen)")
    print(f"""
   Betreff: Missbrauchs-Meldung zu {ip} ({date_short})

   Sehr geehrte Damen und Herren,

   hiermit melde ich einen Missbrauch aus Ihrem Netzbereich.

   Betroffene IP-Adresse:      {ip}  (Netzblock {start or '?'} - {end or '?'})
   ASN / Betreiber:            AS{asn or '?'} - {isp}
   Hostname (PTR):             {ptr}
   Zeitpunkt der Beobachtung:  [TT.MM.JJJJ HH:MM bis HH:MM MEZ]
   Art des Vorfalls:           [z.B. Portscan, Angriff auf SSH, Spam,
                                Phishing, DoS auf meinen Dienst]
   Mein betroffener Dienst:    [eigene IP {own_ip}, Port/Protokoll]
   Log-Auszug:                 [Server-/Firewall-Logzeilen hier einfügen]

   Ich bitte um Prüfung des Vorfalls sowie um Veranlassung geeigneter
   Maßnahmen. Rückfragen beantworte ich unter [Name, E-Mail, Telefon].

   Mit freundlichen Grüßen
   [Dein Name]

   --- Technische Details ---
   Erhoben am:             {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
   Meldende IP:            {own_ip}
   PTR der Verdächtigen:   {ptr}
   Registry/Whois:         {whois_server or 'siehe rdap.org'}
   Datenquellen:           ipwho.is · RDAP · dns.google
""")
    print(f"   {bold('So geht es weiter')}")
    print("   " + dim("1. Platzhalter [ ... ] ausfüllen, Log-Zeilen anhängen"))
    print("   " + dim("2. An die Empfänger-Adresse senden (Antwort meist "
                     "in 24–72 h)"))
    print("   " + dim("3. Bei Straftat: Anzeige bei der Polizei – die "
                     "fordert beim ISP Auskunft an"))
    print("   " + dim("4. Nur echte Vorfälle melden: Falschmeldung = "
                     "Missbrauch des Verfahrens"))
    hint("Es wurde nichts verschickt – nur öffentliche Netzkdaten gelesen.")


# ---------------------------------------------------------------- Menü
COMMANDS = [
    ("RECHERCHE", [
        ("1", "ip", ip_lookup, "IP-Adresse (leer = eigene)"),
        ("2", "dns", dns_lookup, "Domain"),
        ("3", "whois", whois_lookup, "Domain"),
        ("4", "user", username_check, "Username"),
        ("5", "mail", email_triage, "E-Mail-Adresse"),
        ("6", "archive", archive_check, "URL"),
        ("7", "phone", phone_lookup, "Rufnummer, z.B. +49 170 1234567"),
    ]),
    ("NETZ & TECHNIK", [
        ("8", "subnet", subnet_calc, "CIDR, z.B. 192.168.1.0/24"),
        ("9", "hash", hash_tool, "Text oder Hash"),
        ("10", "pw", password_check, "Passwort (lokal)"),
        ("11", "mac", mac_vendor, "MAC-Adresse"),
        ("12", "report", abuse_report, "IP → Abuse-Meldung"),
    ]),
    ("WEB", [
        ("13", "redirect", redirect_check, "URL"),
        ("14", "headers", headers_check, "URL"),
        ("15", "ptr", ptr_lookup, "IP-Adresse"),
        ("16", "cve", cve_search, "Suchbegriff"),
    ]),
]

BY_NUM, BY_KEY = {}, {}
for _group, _items in COMMANDS:
    for _num, _key, _func, _prompt in _items:
        BY_NUM[_num] = (_key, _func, _prompt)
        BY_KEY[_key] = (_num, _func, _prompt)


def print_menu():
    header("OSINT-LOOKUP", "passive Recherche · nur lesen")
    for group, items in COMMANDS:
        pad = max(6, 46 - len(group))
        print(f"\n   {magenta(bold('◆ ' + group))} {dim('─' * pad)}")
        for num, key, _func, prompt in items:
            print(f"     {green('[' + num.rjust(2) + ']')} "
                  f"{bold(key.ljust(10))} {dim(prompt)}")
    print(f"\n   {dim('Nummer oder Modulname wählen · ')}"
          f"{bold('0')} {dim('= Ende')}")


def run(func, arg):
    start = time.time()
    try:
        func(arg)
    except KeyboardInterrupt:
        print(dim("\n   abgebrochen\n"))
        return
    except Exception as e:                      # noqa: BLE001
        print(red(f"\n   Fehler: {e}\n"))
        return
    elapsed = time.time() - start
    print(f"   {dim('·' * 46)}")
    print(f"   {green('✓')} {dim('fertig in')} {bold(f'{elapsed:.1f} s')}")


def main():
    args = sys.argv[1:]

    if args:
        key = args[0].lower()
        if key in BY_KEY:
            func = BY_KEY[key][1]
            run(func, args[1] if len(args) > 1 else "")
        elif key == "ip":
            run(ip_lookup, "")
        else:
            print(__doc__)
        return

    startup()

    while True:
        print_menu()
        try:
            choice = input(f"\n   {bold(cyan('›'))} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice in ("0", "q", "quit", "exit", "ende"):
            print(f"\n   {dim('Bis dann – nur gelesen, nichts verändert.')}\n")
            return
        if choice in BY_NUM:
            key, func, prompt = BY_NUM[choice]
        elif choice in BY_KEY:
            _num, func, prompt = BY_KEY[choice]
        else:
            print(red("   ✗ Unbekannte Auswahl – Nummer oder Modulname "
                      "eingeben."))
            continue

        try:
            value = input(f"   {magenta('▸')} {cyan(prompt)}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        run(func, value)
        print()


if __name__ == "__main__":
    main()
