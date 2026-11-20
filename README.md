# SENTRA — AI-Based SIEM Assistant for Threat Investigation and Reporting

A working prototype of the project in the review deck (Vivekanandha College of Engineering for Women, Dept. of CST):
ask security questions by **text or voice** (English, தமிழ், हिन्दी, Tanglish, Hinglish), get ML-scored incidents mapped to
**MITRE ATT&CK**, an automated **root-cause analysis**, **PDF reports**, **Email / Telegram / Teams alerts**, a **predictive
risk** view, and a **real-time live mode**.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                                             # open http://127.0.0.1:5000
python tests/test_sentra.py                               # optional: 9 self-tests
```
First start trains the severity model (~6 s). Everything works offline with synthetic Windows logs; no API keys needed.

### 3-minute demo script
1. **Dashboard** – KPIs, activity timeline, MITRE coverage, correlated incidents. Click `INC-0005` for root cause, attack path, timeline.
2. **▶ Live attack demo** – the intrusion replays in ~45 s; alerts stream into the feed, severity climbs, and a dry-run notification fires (see `outbox/`).
3. **Chat** (right panel / 💬 on mobile): `Show critical alerts` · `attack eppadi start aachu` · `முக்கிய எச்சரிக்கைகள் காட்டு` · `हमला कैसे शुरू हुआ` · `Investigate 203.0.113.45` · `Forecast` · `Generate report`. Tap 🎤 for voice (Chrome/Edge).
4. **⬇ PDF report** – executive summary, ATT&CK matrix, RCA, timeline, IOCs, recommendations, forecast.

## How each objective in the deck is implemented

| Deck objective | Implementation | File |
|---|---|---|
| Conversational interface over SIEM logs | Chat panel + `/api/chat`; answers built from live analysis data | `siem/assistant.py` |
| Text **and voice** queries | Browser Web Speech API (mic in, optional read-aloud out) | `templates/index.html` |
| Multi-language NLP | Language detection + char-n-gram TF-IDF/LogReg intent classifier + entity extraction (IP, user, host, severity, time window) in 5 languages | `siem/nlp.py`, `siem/i18n.py` |
| ML threat severity + risk scores | RandomForest (P[real attack]) + IsolationForest (behaviour anomaly) + rule weight + intel + asset criticality → 0-100 risk | `siem/ml.py` |
| MITRE ATT&CK mapping | Every rule carries a technique/tactic; matrix on dashboard and in PDF | `siem/mitre.py`, `siem/detection.py` |
| Threat-intel enrichment | AbuseIPDB + VirusTotal when keys are set; offline demo table otherwise | `siem/intel.py` |
| Automated root-cause analysis | Union-find correlation of alerts into incidents; entry vector, causes, propagation path, blast radius, prior-day reconnaissance | `siem/rca.py` |
| Predictive use of historical logs | Trend extrapolation per external IP + decayed exposure per host; early warnings for low-and-slow escalation | `siem/forecast.py` |
| PDF incident reports | ReportLab executive report | `siem/report.py` |
| Real-time Email/Telegram/Teams alerts | SMTP / Bot API / webhook; dry-run to `outbox/` without credentials; de-duplicated, re-notifies on escalation | `siem/notifier.py` |
| Log sources (Splunk / Wazuh / CSV / API) | Upload CSV/JSON/JSONL exports (column aliases matched) or POST to `/api/events` | `siem/ingest.py`, `app.py` |

## Architecture

```
Windows hosts ──► collector/windows_agent.py ─┐            ┌─► Dashboard (SSE live updates)
Winlogbeat / Wazuh / NXLog / CSV upload ──────┼─► POST /api/events ─► rolling buffer
Synthetic generator / live replay ────────────┘            │
                                                           ▼
   rules (14) → threat intel → IsolationForest anomaly → correlation into incidents
        → RandomForest severity + risk score → RCA + MITRE + forecast
                                                           │
                         ┌───────────────┬─────────────────┼───────────────┐
                         ▼               ▼                 ▼               ▼
                   Chat assistant   PDF report     Email/Telegram/Teams   REST API
```

## Making it truly real-time

* **On a Windows machine** (elevated prompt): `python collector/windows_agent.py --server http://SENTRA_HOST:5000 --api-key KEY`
  — it polls the Security log every few seconds and POSTs new events; the dashboard updates over Server-Sent Events.
  Set `SENTRA_API_KEY` on the server so only your agents can write. *The agent was written for Windows and could not be run against a real Windows log in the build environment — test it on a lab machine first.*
* **Production path:** replace the collector with Winlogbeat / Wazuh / NXLog → Kafka or Redis Streams → this analyser;
  store history in OpenSearch/PostgreSQL (TimescaleDB); put a TLS + SSO reverse proxy in front. The analysis currently
  re-runs on the whole in-memory buffer (last 60k events) after each batch, which is fine for demo/lab scale (≈0.5 s per run on ~1.2k events) but would need
  incremental processing at enterprise volume.
* `docker build -t sentra . && docker run -p 5000:5000 -e SENTRA_API_KEY=KEY sentra` (single process only).

## Configuration
Copy `.env.example` and export the variables you need: `ABUSEIPDB_API_KEY`, `VT_API_KEY`, `SMTP_*` + `ALERT_EMAIL_TO`,
`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, `TEAMS_WEBHOOK_URL`, `SENTRA_API_KEY`, `SENTRA_DRY_RUN=1` (never send).

## Honest limitations (say these before the judges ask)
* **Models are trained on synthetic logs.** The ~100 % precision/recall shown in the footer is a benchmark on generated days
  whose attack pattern resembles the training pattern — it is *not* real-world accuracy. For real use, collect labelled alerts and retrain (`SeverityModel.fit`).
* Detection is rule-first (14 explainable rules); ML decides priority, it does not discover unknown attack types on its own beyond the anomaly score.
* Forecasts are trend heuristics, not guarantees. Intel is offline demo data unless API keys are set.
* Voice needs Chrome/Edge (and internet for recognition). PDF reports are English only (built-in fonts).
* The web UI has no login; keep it on localhost or behind an authenticating proxy. "Today/yesterday" are calendar-based; "last N hours" is relative to the latest log time.
* The synthetic IPs are RFC 5737 documentation addresses, never real hosts.

## Likely viva questions
* *Existing SIEMs already have AI — what's new?* Free/offline, Windows-log-focused, **5-language text+voice**, end-to-end alert → RCA → ATT&CK → report → notify without an analyst writing queries, and trend-based early warning from history.
* *How is the risk score computed?* 40 % ML probability + 20 % rule weight + 15 % anomaly + 15 % threat intel + 10 % asset criticality, +2 per extra ATT&CK tactic in the incident.
* *How do you reduce false positives?* Correlation into incidents, context features (off-hours, actor type, success after failures), and decoy cases in training (admin work, build scripts, scanner noise).
* *How would it scale?* Stream via Kafka, incremental windows, OpenSearch storage, per-tenant models.
