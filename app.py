"""SENTRA — AI-Based SIEM Assistant for Threat Investigation and Reporting (Flask app)."""
from __future__ import annotations

import os
import queue
import time
from pathlib import Path

import pandas as pd
from flask import Flask, Response, jsonify, render_template, request, send_from_directory

from siem.assistant import Assistant
from siem.i18n import LANG_NAMES, SPEECH_LANG
from siem.ingest import load_events
from siem.log_generator import generate_logs
from siem.notifier import Notifier
from siem.pipeline import SentraEngine, alert_view, incident_view
from siem.report import generate_report
from siem.state import AppState

BASE = Path(__file__).parent
os.chdir(BASE)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024   # 25 MB log uploads

engine = SentraEngine(models_dir=str(BASE / "models"))
notifier = Notifier(str(BASE / "outbox"))
state = AppState(engine, notifier, report_dir=str(BASE / "reports"))
state.load(generate_logs(seed=int(os.getenv("SENTRA_SEED", "42"))), "synthetic demo logs", announce=False)
assistant = Assistant(state.get, lambda an, inc=None: generate_report(an, state.report_dir, inc), notifier)


def _need_key():
    key = os.getenv("SENTRA_API_KEY", "")
    if key and request.headers.get("X-API-Key") != key:
        return jsonify(error="invalid or missing X-API-Key"), 401
    return None


# ------------------------------------------------------------------ pages
@app.get("/")
def index():
    return render_template("index.html", languages=LANG_NAMES, speech=SPEECH_LANG)


@app.get("/api/health")
def health():
    return jsonify(status="ok", events=int(len(state.get()["df"])))


# ------------------------------------------------------------------ read APIs
@app.get("/api/overview")
def overview():
    an = state.get()
    meta = an["meta"]
    return jsonify(
        stats=an["stats"], source=an["meta"]["source"], intel_mode=meta["intel_mode"], model=meta["model"],
        data_start=meta["data_start"].isoformat(), data_end=meta["data_end"].isoformat(),
        notifier=notifier.configured(), dry_run_forced=notifier.dry_run_forced, live=state.live.info,
        incidents=[incident_view(i) for i in an["incidents"]], forecast=an["forecast"])


@app.get("/api/alerts")
def alerts():
    an = state.get()
    al = an["alerts"]
    for key, attr in (("severity", "severity"), ("host", None), ("user", "user"), ("ip", "src_ip"),
                      ("incident", "incident_id"), ("technique", "technique")):
        v = request.args.get(key)
        if v:
            al = [a for a in al if (v in a["hosts"] if key == "host" else str(a[attr]).lower() == v.lower())]
    q = request.args.get("q", "").lower()
    if q:
        al = [a for a in al if q in (a["name"] + a["description"] + a["user"] + a["src_ip"] + a["host"]).lower()]
    al = sorted(al, key=lambda a: -a["risk"])[: int(request.args.get("limit", 200))]
    return jsonify([alert_view(a) for a in al])


@app.get("/api/incidents/<inc_id>")
def incident(inc_id):
    inc = next((i for i in state.get()["incidents"] if i["incident_id"] == inc_id), None)
    if not inc:
        return jsonify(error="not found"), 404
    out = incident_view(inc)
    out["alerts"] = [alert_view(a) for a in state.get()["alerts"] if a["incident_id"] == inc_id]
    return jsonify(out)


@app.get("/api/events")
def events():
    df = state.get()["df"]
    for col in ("host", "user", "src_ip"):
        if request.args.get(col):
            df = df[df[col] == request.args[col]]
    if request.args.get("event_id"):
        df = df[df["event_id"] == int(request.args["event_id"])]
    df = df.tail(int(request.args.get("limit", 100)))
    cols = ["timestamp", "host", "event_id", "event_name", "user", "src_ip", "logon_type", "process", "command_line", "target_object"]
    return jsonify(json_records(df[cols]))


def json_records(df: pd.DataFrame):
    out = df.copy()
    out["timestamp"] = out["timestamp"].astype(str)
    return out.to_dict(orient="records")


# ------------------------------------------------------------------ actions
@app.post("/api/chat")
def chat():
    body = request.get_json(force=True, silent=True) or {}
    text = (body.get("message") or "").strip()
    if not text:
        return jsonify(error="empty message"), 400
    return jsonify(assistant.ask(text[:500], lang_hint=body.get("lang") if body.get("lang") != "auto" else None))


@app.post("/api/report")
def report():
    body = request.get_json(force=True, silent=True) or {}
    path = generate_report(state.get(), state.report_dir, body.get("incident_id"))
    return jsonify(name=path.name, url=f"/reports/{path.name}")


@app.get("/reports/<path:name>")
def get_report(name):
    return send_from_directory(state.report_dir, name, as_attachment=request.args.get("dl") == "1")


@app.post("/api/notify")
def notify():
    body = request.get_json(force=True, silent=True) or {}
    an = state.get()
    inc = next((i for i in an["incidents"] if i["incident_id"] == body.get("incident_id")), an["incidents"][0] if an["incidents"] else None)
    if not inc:
        return jsonify(error="no incidents"), 404
    pdf = generate_report(an, state.report_dir, inc["incident_id"])
    return jsonify(incident=inc["incident_id"], results=notifier.send_incident(inc, an, body.get("channels"), pdf))


@app.post("/api/upload")
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify(error="no file"), 400
    try:
        df = load_events(f.read(), f.filename or "upload.csv")
    except Exception as exc:
        return jsonify(error=f"{type(exc).__name__}: {exc}"), 400
    if df.empty:
        return jsonify(error="no usable events in file"), 400
    state.live.stop()
    state.load(df, f"upload: {f.filename}", announce=False)
    return jsonify(events=int(len(df)), alerts=state.get()["stats"]["alerts"])


@app.post("/api/events")
def ingest_events():
    """Real-time ingestion endpoint used by collector/windows_agent.py (and any log shipper)."""
    denied = _need_key()
    if denied:
        return denied
    body = request.get_json(force=True, silent=True)
    rows = body.get("events") if isinstance(body, dict) else body
    if not isinstance(rows, list) or not rows:
        return jsonify(error="expected a JSON list of events"), 400
    try:
        df = load_events(pd.DataFrame(rows).to_json(orient="records").encode(), "batch.json")
    except Exception as exc:
        return jsonify(error=f"{type(exc).__name__}: {exc}"), 400
    state.append(df)
    return jsonify(accepted=int(len(df)), total=int(len(state.get()["df"])))


@app.post("/api/demo/reset")
def reset():
    body = request.get_json(force=True, silent=True) or {}
    state.live.stop()
    state.load(generate_logs(seed=int(body.get("seed", 42))), "synthetic demo logs", announce=False)
    return jsonify(ok=True)


@app.post("/api/live/start")
def live_start():
    body = request.get_json(force=True, silent=True) or {}
    state.live.start(generate_logs(seed=int(body.get("seed", 42))), speed=float(body.get("speed", 90)))
    return jsonify(state.live.info)


@app.post("/api/live/stop")
def live_stop():
    state.live.stop()
    return jsonify(state.live.info)


@app.get("/api/live/status")
def live_status():
    return jsonify(state.live.info)


@app.get("/api/stream")
def stream():
    q = state.subscribe()

    def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    yield f"data: {q.get(timeout=15)}\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        finally:
            state.unsubscribe(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    host = os.getenv("SENTRA_HOST", "127.0.0.1")
    port = int(os.getenv("SENTRA_PORT", "5000"))
    print(f"\n  SENTRA running → http://{host}:{port}   (threat intel: {engine.intel.mode}; notifications: "
          f"{'live' if any(notifier.configured().values()) and not notifier.dry_run_forced else 'dry-run → outbox/'})\n")
    app.run(host=host, port=port, threaded=True, debug=False)
