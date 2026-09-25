# OSINT-Lookup

**Passive Recherche im Terminal – 16 Module, nur lesen, kein Login.**

`OSINT-Lookup` fragt ausschließlich **öffentliche** Quellen ab (DNS/DoH, RDAP, GeoIP-Datenbanken, NIST NVD, Wayback Machine). Es wird nichts verändert, nichts angemeldet und kein Passwort übertragen – auch der Passwort-Check läuft komplett lokal.

## Installation

### Variante A – eine Zeile (Windows, PowerShell)

```powershell
irm https://github.com/foxlana089-png/osint-lookup/releases/latest/download/install.ps1 | iex
```

### Variante B – ZIP herunterladen

1. [osint-lookup.zip](https://github.com/foxlana089-png/osint-lookup/releases/latest/download/osint-lookup.zip) laden und entpacken
2. `install.bat` doppelklicken (prüft Python, installiert die zwei Pakete, setzt den Desktop-Link)
3. Desktop-Link **osint** startet das Tool

### Variante C – aus dem Repository

```bash
git clone https://github.com/foxlana089-png/osint-lookup.git
cd osint-lookup
pip install -r requirements.txt
python osint.py
```

**Voraussetzung:** Python 3.8+ (`python` muss im PATH sein) und Internetzugang zu den öffentlichen APIs.

## Module

| Gruppe | Befehl | Beschreibung |
| --- | --- | --- |
| Recherche | `ip` | IP-Lookup: Standort, Netz, Routing, Genauigkeit, Reputation |
| Recherche | `dns` | A, AAAA, CNAME, MX, NS, TXT, SOA über DoH |
| Recherche | `whois` | RDAP: Registrar, Status, Termine, Abuse-Kontakt |
| Recherche | `user` | Username auf 9 Plattformen prüfen |
| Recherche | `mail` | E-Mail-Triage: Anbieter, SPF/DMARC/BIMI/MTA-STS, DNSSEC, Gravatar |
| Recherche | `archive` | Wayback Machine: ältere Zustände einer URL |
| Recherche | `phone` | Rufnummer: Land, Typ, Anbieter, Zeitzone, Wählhilfe |
| Netz | `subnet` | Subnetz-Rechner (CIDR) |
| Netz | `hash` | Hash erkennen oder erzeugen |
| Netz | `pw` | Passwort-Stärke – **komplett lokal** |
| Netz | `mac` | MAC-Adress-Vendor (OUI) |
| Netz | `report` | Fertige Abuse-Meldung für den Provider des Netzes |
| Web | `redirect` | Redirect-Kette / URL-Entkürzung auflösen |
| Web | `headers` | HTTP-Header + Security-Header-Bewertung |
| Web | `ptr` | Reverse-DNS (PTR) |
| Web | `cve` | CVE-Suche über NIST NVD |

## Beispiele

```bash
python osint.py ip 1.1.1.1
python osint.py dns example.com
python osint.py mail info@example.com
python osint.py phone "+49 170 1234567"
python osint.py subnet 192.168.1.0/24
python osint.py report 203.0.113.44
```

Ohne Argumente startet eine Menüführung:

```bash
python osint.py
```

## Was das Tool bewusst nicht kann

* keine Personendaten (Name, Straße, E-Mail, Telefon) hinter einer IP-Adresse – das weiß nur der Provider, Auskunft nur an Behörden
* keine Anmeldung, keine Passwörter, keine Brute-Force- oder Scan-Verfahren
* keine veränderten/„gekauften" Follower, keine Ban-Umgehung

## Rechtlicher Hinweis

Nur für rechtmäßige Zwecke nutzbar (eigene Systeme, Recherche, Sicherheitsprüfungen). Missbrauch – insbesondere Stalking, Belästigung oder das Zusammenstellen personenbezogener Daten – ist nicht gestattet und kann strafbar sein.

## Lizenz

MIT – siehe [LICENSE](LICENSE).
