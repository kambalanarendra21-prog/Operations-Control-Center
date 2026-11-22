import os
import io
import csv
import json
import time
import sqlite3
from datetime import datetime
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Operations Control Center")
templates = Jinja2Templates(directory="templates")

# Environment variable fallbacks
DEFAULT_TOKEN = os.environ.get("CF_API_TOKEN", "").strip()
DEFAULT_DYNADOT_KEY = os.environ.get("DYNADOT_API_KEY", "").strip()
DEFAULT_AWS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
DEFAULT_AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
DEFAULT_GOOGLE_TOKEN = os.environ.get("GOOGLE_OAUTH_TOKEN", "").strip()
DEFAULT_YAHOO_COOKIE = os.environ.get("YAHOO_SENDERHUB_COOKIE", "").strip()
DEFAULT_LLM_KEY = os.environ.get("OPENAI_API_KEY", "").strip()

TIMEOUT = 25
DB_PATH = "jobs.db"
MAX_DOMAINS_PER_RUN = 1000


# ==========================================
# SQLITE PERSISTENT JOB QUEUE
# ==========================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            tab_id TEXT NOT NULL DEFAULT 'dns',
            endpoint TEXT NOT NULL,
            label TEXT NOT NULL,
            total INTEGER NOT NULL,
            ok INTEGER NOT NULL,
            fail INTEGER NOT NULL,
            results_json TEXT NOT NULL
        )
    """)
    try:
        conn.execute("ALTER TABLE jobs ADD COLUMN tab_id TEXT NOT NULL DEFAULT 'dns'")
    except Exception:
        pass
    conn.commit()
    conn.close()


init_db()


# ==========================================
# RESILIENT HTTP & PARALLEL STREAM HELPERS
# ==========================================
def build_resilient_session(headers: Optional[dict] = None) -> requests.Session:
    s = requests.Session()
    retry_strategy = Retry(
        total=4,
        backoff_factor=1.2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "POST", "PATCH"],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=24, pool_maxsize=24)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if headers:
        s.headers.update(headers)
    return s


SHARED_HTTP = build_resilient_session()


def create_session(api_token: str) -> requests.Session:
    return build_resilient_session({
        "Authorization": f"Bearer {api_token.strip()}",
        "Content-Type": "application/json",
    })


def sse_response(generator):
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def run_parallel_stream(request: Request, items: list, worker_fn, concurrency: int = 6):
    total = len(items)
    if total == 0:
        yield f"data: {json.dumps({'done': True})}\n\n"
        return

    max_workers = max(1, min(int(concurrency or 6), 12, total))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_idx = {
            pool.submit(worker_fn, idx, total, item): idx
            for idx, item in enumerate(items, 1)
        }
        for fut in as_completed(future_to_idx):
            if await request.is_disconnected():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            idx = future_to_idx[fut]
            try:
                res = fut.result()
            except Exception as exc:
                res = {
                    "index": idx,
                    "total": total,
                    "domain": str(items[idx - 1]),
                    "account": "-",
                    "target": "Worker",
                    "result": str(exc).strip() or type(exc).__name__,
                    "extra": "-",
                    "ok": False,
                }
            if isinstance(res, dict):
                res.setdefault("index", idx)
                res.setdefault("total", total)
                yield f"data: {json.dumps(res)}\n\n"

    yield f"data: {json.dumps({'done': True})}\n\n"


def extract_root_and_sub(hostname: str) -> Tuple[str, str]:
    h = hostname.strip().rstrip(".").lower()
    if h.startswith("http://"):
        h = h[7:]
    elif h.startswith("https://"):
        h = h[8:]
    h = h.split("/")[0].split(":")[0].strip()
    if not h:
        return "", ""

    parts = h.split(".")
    if len(parts) <= 2:
        return h, "@"

    multi_tlds = ("co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "org.in", "com.br", "co.jp")
    if len(parts) >= 3 and ".".join(parts[-2:]) in multi_tlds:
        root = ".".join(parts[-3:])
        sub = ".".join(parts[:-3]) or "@"
        return root, sub

    root = ".".join(parts[-2:])
    sub = ".".join(parts[:-2]) or "@"
    return root, sub


def get_zone_cached(session: requests.Session, domain: str, cache: dict) -> Tuple[Optional[str], str]:
    clean = domain.strip().rstrip(".").lower()
    if clean in cache:
        return cache[clean]

    try:
        r = session.get(
            "https://api.cloudflare.com/client/v4/zones",
            params={"name": clean, "per_page": 50},
            timeout=TIMEOUT,
        ).json()
        if r.get("success") and r.get("result"):
            zones = r["result"]
            active_zones = [z for z in zones if z.get("status") == "active"]
            z = active_zones[0] if active_zones else zones[0]
            acc_name = z.get("account", {}).get("name", "Default Account")
            if z.get("status") != "active":
                acc_name = f"{acc_name} [CF:{z.get('status')}]"
            cache[clean] = (z["id"], acc_name)
            return cache[clean]
    except Exception:
        pass

    cache[clean] = (None, "-")
    return None, "-"


def manage_dns_record(
    session: requests.Session,
    zone_id: str,
    root_domain: str,
    action: str,
    rtype: str,
    name: str,
    content: str = "",
    proxied: bool = False,
    priority: Optional[int] = None,
    ttl: int = 1,
) -> Tuple[bool, str]:
    clean_root = root_domain.strip().rstrip(".").lower()
    clean_name = name.strip().rstrip(".").lower()
    if clean_name in ("@", "", clean_root):
        fqdn = clean_root
    elif clean_name.endswith(f".{clean_root}"):
        fqdn = clean_name
    else:
        fqdn = f"{clean_name}.{clean_root}"

    rtype_up = rtype.strip().upper()
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"

    try:
        r = session.get(url, params={"type": rtype_up, "name": fqdn, "per_page": 100}, timeout=TIMEOUT).json()
        existing = r.get("result", []) if r.get("success") else []

        if action == "delete":
            if not existing:
                return True, f"No {rtype_up} found on {name}"
            deleted = 0
            for rec in existing:
                if content and content.strip() and rec.get("content", "").strip('"') != content.strip().strip('"'):
                    continue
                dr = session.delete(f"{url}/{rec['id']}", timeout=TIMEOUT).json()
                if dr.get("success"):
                    deleted += 1
            return True, f"Deleted {deleted} {rtype_up} ({name})"

        if action == "add_if_missing":
            for rec in existing:
                if not content or rec.get("content", "").strip('"') == content.strip().strip('"'):
                    return True, f"Exists ({rtype_up} {name})"

        payload = {
            "type": rtype_up,
            "name": fqdn,
            "content": content.strip(),
            "ttl": int(ttl) if ttl else 1,
            "proxied": bool(proxied) if rtype_up in ("A", "AAAA", "CNAME") else False,
        }
        if rtype_up in ("MX", "SRV", "URI") and priority is not None and str(priority).strip() != "":
            payload["priority"] = int(priority)

        if action == "replace" and existing:
            rec_id = existing[0]["id"]
            for extra in existing[1:]:
                try:
                    session.delete(f"{url}/{extra['id']}", timeout=TIMEOUT)
                except Exception:
                    pass
            ur = session.put(f"{url}/{rec_id}", json=payload, timeout=TIMEOUT).json()
            if ur.get("success"):
                return True, f"Updated {rtype_up} ({name})"
            err = (ur.get("errors") or [{}])[0].get("message", "Update failed")
            return False, err

        cr = session.post(url, json=payload, timeout=TIMEOUT).json()
        if cr.get("success"):
            return True, f"Added {rtype_up} ({name})"
        err = (cr.get("errors") or [{}])[0].get("message", "Create failed")
        return False, err
    except Exception as e:
        return False, str(e)[:80]


def verify_cname_via_doh(fqdn: str, expected_target: str) -> bool:
    try:
        r = SHARED_HTTP.get(
            "https://dns.google/resolve",
            params={"name": fqdn.strip().rstrip("."), "type": "CNAME"},
            timeout=8,
        ).json()
        if r.get("Status") != 0:
            return False
        exp = expected_target.strip().rstrip(".").lower()
        for ans in r.get("Answer", []):
            if ans.get("type") == 5:
                data = ans.get("data", "").strip().rstrip(".").lower()
                if data == exp:
                    return True
    except Exception:
        pass
    return False


# ==========================================
# DASHBOARD UI & UTILITY ENDPOINTS
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "has_env_token": bool(DEFAULT_TOKEN),
            "has_env_dynadot": bool(DEFAULT_DYNADOT_KEY),
            "has_env_aws": bool(DEFAULT_AWS_KEY and DEFAULT_AWS_SECRET),
            "has_env_google": bool(DEFAULT_GOOGLE_TOKEN),
            "has_env_yahoo": bool(DEFAULT_YAHOO_COOKIE),
            "has_env_llm": bool(DEFAULT_LLM_KEY),
        },
    )


@app.get("/sample-csv")
async def sample_csv():
    content = (
        "domain,action,type,name,content,proxied,priority,ttl,ssl_mode\n"
        "example1.com,replace,A,@,3.23.10.37,true,,1,flexible\n"
        "example1.com,add_if_missing,TXT,@,v=spf1 include:amazonses.com ~all,false,,1,\n"
        "example1.com,add_if_missing,TXT,_dmarc,v=DMARC1; p=none;,false,,1,\n"
    )
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sample_bulk_dns.csv"},
    )


@app.get("/sample-yahoo-csv")
async def sample_yahoo_csv():
    content = (
        "domain,verification_token\n"
        "example1.com,yahoo-verification-key=abc123xyz\n"
        "example2.com,yahoo-verification-key=def456uvw\n"
    )
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sample_yahoo_tokens.csv"},
    )


@app.post("/api/accounts")
@app.post("/api/google-token-info")
async def google_token_info(google_oauth_token: str = Form("")):
    tok = (google_oauth_token or "").strip() or DEFAULT_GOOGLE_TOKEN
    if not tok:
        return {"ok": False, "error": "Missing Google OAuth token"}
    try:
        r = SHARED_HTTP.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"access_token": tok},
            timeout=10,
        )
        data = r.json() if r.text else {}
        if r.status_code != 200 or "error" in data:
            return {"ok": False, "error": data.get("error_description") or data.get("error") or "Token expired or invalid"}
        expires_in = int(data.get("expires_in", 0))
        return {
            "ok": expires_in > 0,
            "expires_in": expires_in,
            "email": data.get("email", ""),
            "scope": data.get("scope", ""),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:80]}
async def list_cf_accounts(api_token: str = Form("")):
    token = api_token.strip() or DEFAULT_TOKEN
    if not token:
        return {"success": False, "error": "Missing Cloudflare API Token"}
    try:
        s = create_session(token)
        r = s.get("https://api.cloudflare.com/client/v4/accounts", params={"per_page": 50}, timeout=TIMEOUT).json()
        if not r.get("success"):
            err = (r.get("errors") or [{}])[0].get("message", "Failed to load accounts")
            return {"success": False, "error": err}
        accounts = [{"id": a["id"], "name": a["name"]} for a in r.get("result", [])]
        return {"success": True, "accounts": accounts}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==========================================
# JOB HISTORY ENDPOINTS (TAB 12)
# ==========================================
@app.get("/api/jobs")
async def get_jobs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, created_at, tab_id, endpoint, label, total, ok, fail FROM jobs ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return {"jobs": [dict(r) for r in rows]}


@app.get("/api/jobs/{job_id}")
async def get_job_detail(job_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    conn.close()
    if not row:
        return {"error": "Job not found"}
    return {
        "id": row["id"],
        "tab_id": row["tab_id"],
        "endpoint": row["endpoint"],
        "label": row["label"],
        "results": json.loads(row["results_json"]),
    }


@app.post("/api/jobs/save")
async def save_job(request: Request):
    data = await request.json()
    results = data.get("results", [])
    ok_count = sum(1 for r in results if r.get("ok"))
    fail_count = len(results) - ok_count
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO jobs (created_at, tab_id, endpoint, label, total, ok, fail, results_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
            data.get("tab_id", "dns"),
            data.get("endpoint", ""),
            data.get("label", "batch"),
            len(results),
            ok_count,
            fail_count,
            json.dumps(results),
        ),
    )
    conn.commit()
    conn.close()
    return {"saved": True}


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}


# ==========================================
# TAB 1: BULK DNS
# ==========================================
@app.post("/api/bulk-dns")
async def bulk_dns(
    request: Request,
    domains_text: str = Form(""),
    action: str = Form("replace"),
    rtype: str = Form("A"),
    name: str = Form("@"),
    content: str = Form(""),
    priority: str = Form(""),
    ttl: int = Form(1),
    ssl_mode: str = Form(""),
    proxied: str = Form(""),
    dry_run: str = Form(""),
    request_delay_ms: int = Form(0),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    is_proxied = proxied == "true"
    is_dry_run = dry_run == "true"
    prio_val = int(priority) if priority.strip().isdigit() else None
    delay_sec = max(0, min(int(request_delay_ms or 0), 5000)) / 1000.0
    session = create_session(cf_token)
    cache = {}

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": dom, "account": "-", "target": f"{rtype} ({name})", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            if is_dry_run:
                return {
                    "index": idx, "total": total, "domain": dom, "account": acc,
                    "target": f"{rtype} ({name}) → {content or 'ALL'}",
                    "result": f"[DRY-RUN] Would {action} {rtype} on {root}",
                    "extra": f"SSL: {ssl_mode or 'unchanged'}", "ok": True,
                }

            ok, msg = manage_dns_record(session, zone_id, root, action, rtype, name, content, is_proxied, prio_val, ttl)
            extra = "-"
            if ok and ssl_mode:
                sr = session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", json={"value": ssl_mode}, timeout=TIMEOUT).json()
                extra = f"SSL: {ssl_mode}" if sr.get("success") else "SSL Failed"

            if delay_sec > 0:
                time.sleep(delay_sec)

            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"{rtype} ({name})", "result": msg, "extra": extra, "ok": ok}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": f"{rtype} ({name})", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 2: CSV MULTI-RECORD UPLOAD
# ==========================================
@app.post("/api/bulk-csv")
async def bulk_csv(
    request: Request,
    csv_file: UploadFile = File(...),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    raw = (await csv_file.read()).decode("utf-8-sig")
    rows = [r for r in csv.DictReader(io.StringIO(raw)) if (r.get("domain") or "").strip()][:MAX_DOMAINS_PER_RUN]
    session = create_session(cf_token)
    cache = {}

    def work(idx: int, total: int, row: dict) -> dict:
        dom = (row.get("domain") or "").strip().lower()
        root, _ = extract_root_and_sub(dom)
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "CSV Row", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            act = (row.get("action") or "replace").strip().lower()
            rt = (row.get("type") or "A").strip().upper()
            nm = (row.get("name") or "@").strip()
            cnt = (row.get("content") or "").strip()
            prx = str(row.get("proxied") or "").strip().lower() in ("true", "1", "yes")
            prio = int(row["priority"]) if str(row.get("priority") or "").strip().isdigit() else None
            ttl_v = int(row["ttl"]) if str(row.get("ttl") or "").strip().isdigit() else 1
            ssl_v = (row.get("ssl_mode") or "").strip().lower()

            ok, msg = manage_dns_record(session, zone_id, root, act, rt, nm, cnt, prx, prio, ttl_v)
            extra = "-"
            if ssl_v:
                sr = session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", json={"value": ssl_v}, timeout=TIMEOUT).json()
                extra = f"SSL: {ssl_v}" if sr.get("success") else "SSL Failed"

            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"{rt} ({nm})", "result": msg, "extra": extra, "ok": ok}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "CSV Row", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, rows, work, concurrency=6))


# ==========================================
# TAB 3: SSL & CACHE PURGE
# ==========================================
@app.post("/api/bulk-zone-settings")
async def bulk_zone_settings(
    request: Request,
    domains_text: str = Form(""),
    ssl_mode: str = Form(""),
    always_https: str = Form(""),
    auto_https_rewrites: str = Form(""),
    purge_cache: str = Form(""),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    session = create_session(cf_token)
    cache = {}

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "SSL/Cache", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            updates = []
            ok_all = True
            if ssl_mode:
                r = session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", json={"value": ssl_mode}, timeout=TIMEOUT).json()
                updates.append(f"SSL={ssl_mode}" if r.get("success") else "SSL Err")
                ok_all = ok_all and r.get("success", False)
            if always_https:
                r = session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/always_use_https", json={"value": always_https}, timeout=TIMEOUT).json()
                updates.append(f"HTTPS={always_https}" if r.get("success") else "HTTPS Err")
            if auto_https_rewrites:
                r = session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/automatic_https_rewrites", json={"value": auto_https_rewrites}, timeout=TIMEOUT).json()
                updates.append(f"Rewrites={auto_https_rewrites}" if r.get("success") else "Rewrites Err")
            if purge_cache == "true":
                r = session.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache", json={"purge_everything": True}, timeout=TIMEOUT).json()
                updates.append("Cache Purged" if r.get("success") else "Purge Err")

            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": "Zone SSL/Cache", "result": ", ".join(updates) or "No Changes Selected", "extra": "-", "ok": ok_all}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "SSL/Cache", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 4: BULK REDIRECTS
# ==========================================
@app.post("/api/bulk-redirect")
async def bulk_redirect(
    request: Request,
    domains_text: str = Form(""),
    redirect_preset: str = Form("root_to_subdomain"),
    subdomain_prefix: str = Form("www"),
    target_url: str = Form(""),
    status_code: int = Form(301),
    preserve_path: str = Form(""),
    ensure_proxied_root: str = Form(""),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    session = create_session(cf_token)
    cache = {}

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": root, "account": "-", "target": "Redirect", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            if ensure_proxied_root == "true":
                manage_dns_record(session, zone_id, root, "add_if_missing", "A", "@", "192.0.2.1", proxied=True)

            if redirect_preset == "root_to_subdomain":
                sub = subdomain_prefix.strip().strip(".") or "www"
                src_pattern = f"{root}/*"
                dest = f"https://{sub}.{root}/$1" if preserve_path == "true" else f"https://{sub}.{root}/"
            else:
                src_pattern = f"*{root}/*"
                raw_dest = target_url.strip().replace("{domain}", root)
                if not raw_dest.startswith("http"):
                    raw_dest = f"https://{raw_dest}"
                dest = f"{raw_dest.rstrip('/')}/$2" if (preserve_path == "true" and "$2" not in raw_dest) else raw_dest

            pr_payload = {
                "targets": [{"target": "url", "constraint": {"operator": "matches", "value": src_pattern}}],
                "actions": [{"id": "forwarding_url", "value": {"url": dest, "status_code": int(status_code)}}],
                "priority": 1,
                "status": "active",
            }
            r = session.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules", json=pr_payload, timeout=TIMEOUT).json()
            ok = r.get("success", False)
            msg = f"{status_code} → {dest}" if ok else (r.get("errors") or [{}])[0].get("message", "Page Rule Failed")
            return {"index": idx, "total": total, "domain": root, "account": acc, "target": src_pattern, "result": msg, "extra": "-", "ok": ok}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "Redirect", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 5: ZONE PROVISIONING & NS FETCHER
# ==========================================
@app.post("/api/bulk-provision")
async def bulk_provision(
    request: Request,
    domains_text: str = Form(""),
    account_id: str = Form(""),
    mode: str = Form("create_and_fetch"),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    session = create_session(cf_token)

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            r = session.get("https://api.cloudflare.com/client/v4/zones", params={"name": root}, timeout=TIMEOUT).json()
            zones = r.get("result", []) if r.get("success") else []
            if zones:
                active_zones = [z for z in zones if z.get("status") == "active"]
                z = active_zones[0] if active_zones else zones[0]
                ns = ", ".join(z.get("name_servers", []))
                acc = z.get("account", {}).get("name", "-")
                return {"index": idx, "total": total, "domain": root, "account": acc, "target": "Existing Zone", "result": ns or "No NS", "extra": z.get("status", "-"), "ok": True}

            if mode == "fetch_only":
                return {"index": idx, "total": total, "domain": root, "account": "-", "target": "Fetch NS", "result": "Zone Not Found", "extra": "-", "ok": False}

            if not account_id:
                return {"index": idx, "total": total, "domain": root, "account": "-", "target": "Create Zone", "result": "Select Target Account First", "extra": "-", "ok": False}

            cr = session.post(
                "https://api.cloudflare.com/client/v4/zones",
                json={"name": root, "account": {"id": account_id}, "jump_start": False, "type": "full"},
                timeout=TIMEOUT,
            ).json()
            if cr.get("success"):
                z = cr["result"]
                ns = ", ".join(z.get("name_servers", []))
                acc = z.get("account", {}).get("name", "-")
                return {"index": idx, "total": total, "domain": root, "account": acc, "target": "Created Zone", "result": ns, "extra": "Pending NS", "ok": True}

            err = (cr.get("errors") or [{}])[0].get("message", "Create Zone Failed")
            return {"index": idx, "total": total, "domain": root, "account": "-", "target": "Create Zone", "result": err, "extra": "-", "ok": False}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "Provision", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 6: DNS AUDITOR & BACKUP
# ==========================================
@app.post("/api/bulk-audit")
async def bulk_audit(
    request: Request,
    domains_text: str = Form(""),
    filter_type: str = Form(""),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    session = create_session(cf_token)
    cache = {}

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": root, "account": "-", "target": "DNS Audit", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            params = {"per_page": 200}
            if filter_type:
                params["type"] = filter_type
            r = session.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", params=params, timeout=TIMEOUT).json()
            recs = r.get("result", []) if r.get("success") else []
            summary = " | ".join(
                f"{rec['type']} {rec['name']}→{rec['content']}{'(P)' if rec.get('proxied') else ''}"
                for rec in recs
            ) or "No matching records"

            return {"index": idx, "total": total, "domain": root, "account": acc, "target": f"{len(recs)} Records", "result": summary, "extra": filter_type or "ALL", "ok": True}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "DNS Audit", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 7: DYNADOT -> CLOUDFLARE MIGRATION
# ==========================================
@app.post("/api/dynadot-sync")
async def dynadot_sync(
    request: Request,
    domains_text: str = Form(""),
    account_id: str = Form(""),
    dynadot_key: str = Form(""),
    ssl_mode: str = Form("flexible"),
    always_https: str = Form("on"),
    auto_https_rewrites: str = Form(""),
    security_level: str = Form(""),
    dyna_renew: str = Form(""),
    import_dynadot_dns: str = Form(""),
    trigger_activation_check: str = Form(""),
    add_custom_records: str = Form(""),
    custom_records_json: str = Form("[]"),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    d_key = dynadot_key.strip() or DEFAULT_DYNADOT_KEY
    if not cf_token or not d_key or not account_id:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare Token, Target Account, or Dynadot API Key'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    custom_recs = json.loads(custom_records_json or "[]")
    session = create_session(cf_token)

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            zr = session.get("https://api.cloudflare.com/client/v4/zones", params={"name": root}, timeout=TIMEOUT).json()
            if zr.get("success") and zr.get("result"):
                zones = zr["result"]
                active_zones = [z for z in zones if z.get("status") == "active"]
                z = active_zones[0] if active_zones else zones[0]
            else:
                cr = session.post(
                    "https://api.cloudflare.com/client/v4/zones",
                    json={"name": root, "account": {"id": account_id}, "jump_start": False, "type": "full"},
                    timeout=TIMEOUT,
                ).json()
                if not cr.get("success"):
                    err = (cr.get("errors") or [{}])[0].get("message", "Zone Create Failed")
                    return {"index": idx, "total": total, "domain": root, "account": "-", "target": "CF Zone", "result": err, "extra": "-", "ok": False}
                z = cr["result"]

            zone_id = z["id"]
            acc = z.get("account", {}).get("name", "-")
            ns_list = z.get("name_servers", [])

            if import_dynadot_dns == "true":
                dr = SHARED_HTTP.get(
                    "https://api.dynadot.com/api3.json",
                    params={"key": d_key, "command": "get_dns", "domain": root},
                    timeout=TIMEOUT,
                ).json()
                main_recs = dr.get("GetDnsResponse", {}).get("GetDns", {}).get("MainDomains", [])
                for m in main_recs:
                    if str(m.get("RecordType", "")).upper() == "A" and m.get("Value"):
                        manage_dns_record(session, zone_id, root, "add_if_missing", "A", "@", m["Value"], proxied=True)

            ns_params = {"key": d_key, "command": "set_ns", "domain": root}
            for i, ns in enumerate(ns_list):
                ns_params[f"ns{i}"] = ns
            ns_resp = SHARED_HTTP.get("https://api.dynadot.com/api3.json", params=ns_params, timeout=TIMEOUT).json()
            ns_ok = ns_resp.get("SetNsResponse", {}).get("Status") == "success"

            if dyna_renew in ("auto", "donot"):
                SHARED_HTTP.get(
                    "https://api.dynadot.com/api3.json",
                    params={"key": d_key, "command": "set_renew_option", "domain": root, "renew_option": dyna_renew},
                    timeout=TIMEOUT,
                )

            if ssl_mode:
                session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", json={"value": ssl_mode}, timeout=TIMEOUT)
            if always_https:
                session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/always_use_https", json={"value": always_https}, timeout=TIMEOUT)
            if auto_https_rewrites:
                session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/automatic_https_rewrites", json={"value": auto_https_rewrites}, timeout=TIMEOUT)
            if security_level:
                session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level", json={"value": security_level}, timeout=TIMEOUT)

            if add_custom_records == "true":
                for rec in custom_recs:
                    cnt = str(rec.get("content", "")).replace("{domain}", root)
                    nm = str(rec.get("name", "@")).replace("{domain}", root)
                    prio = int(rec["priority"]) if str(rec.get("priority", "")).strip().isdigit() else None
                    manage_dns_record(session, zone_id, root, "replace", rec.get("type", "A"), nm, cnt, bool(rec.get("proxied")), prio)

            if trigger_activation_check == "true":
                session.put(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/activation_check", timeout=TIMEOUT)

            return {
                "index": idx, "total": total, "domain": root, "account": acc,
                "target": ", ".join(ns_list),
                "result": "Dynadot NS Synced → Cloudflare" if ns_ok else f"Dynadot NS Warning: {ns_resp}",
                "extra": f"SSL: {ssl_mode or 'unchanged'}", "ok": ns_ok,
            }
        except Exception as exc:
            return {"index": idx, "total": total, "domain": root, "account": "-", "target": "Dynadot Sync", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 8: AWS S3 DEPLOY / VERIFY / TEARDOWN
# ==========================================
@app.post("/api/bulk-s3-deploy")
async def bulk_s3_deploy(
    request: Request,
    domains_text: str = Form(""),
    s3_operation: str = Form("deploy"),
    aws_access_key: str = Form(""),
    aws_secret_key: str = Form(""),
    aws_region: str = Form("us-east-1"),
    add_www_cname: str = Form(""),
    set_flexible_ssl: str = Form(""),
    always_https: str = Form(""),
    verify_after_deploy: str = Form(""),
    dry_run: str = Form(""),
    request_delay_ms: int = Form(0),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    ak = aws_access_key.strip() or DEFAULT_AWS_KEY
    sk = aws_secret_key.strip() or DEFAULT_AWS_SECRET
    if not cf_token or not ak or not sk:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare Token or AWS Credentials'})}\n\n"
        return sse_response(err_stream())

    region = aws_region.strip() or "us-east-1"
    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    is_dry_run = dry_run == "true"
    delay_sec = max(0, min(int(request_delay_ms or 0), 5000)) / 1000.0
    s3 = boto3.client("s3", region_name=region, aws_access_key_id=ak, aws_secret_access_key=sk)
    session = create_session(cf_token)
    cache = {}

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        zone_id, acc = get_zone_cached(session, root, cache)
        try:
            if is_dry_run:
                return {
                    "index": idx, "total": total, "domain": dom, "account": acc,
                    "target": f"S3 ({region}) • {s3_operation}",
                    "result": f"[DRY-RUN] Would run '{s3_operation}' for {dom}",
                    "extra": "Preview Only", "ok": True,
                }

            if s3_operation == "verify_only":
                r = SHARED_HTTP.get(f"https://{dom}", timeout=8)
                return {"index": idx, "total": total, "domain": dom, "account": acc, "target": "HTTP Check", "result": f"HTTP {r.status_code}", "extra": "-", "ok": r.status_code == 200}

            if s3_operation == "teardown":
                try:
                    objs = s3.list_objects_v2(Bucket=dom).get("Contents", [])
                    if objs:
                        s3.delete_objects(Bucket=dom, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
                    s3.delete_bucket(Bucket=dom)
                except Exception:
                    pass
                if zone_id:
                    manage_dns_record(session, zone_id, root, "delete", "CNAME", "@")
                    manage_dns_record(session, zone_id, root, "delete", "CNAME", "www")
                return {"index": idx, "total": total, "domain": dom, "account": acc, "target": "Teardown", "result": "Deleted S3 Bucket & CF CNAMEs", "extra": "-", "ok": True}

            try:
                if region == "us-east-1":
                    s3.create_bucket(Bucket=dom)
                else:
                    s3.create_bucket(Bucket=dom, CreateBucketConfiguration={"LocationConstraint": region})
            except s3.exceptions.BucketAlreadyOwnedByYou:
                pass

            s3.put_public_access_block(
                Bucket=dom,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            )
            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{dom}/*",
                }],
            }
            s3.put_bucket_policy(Bucket=dom, Policy=json.dumps(policy))
            s3.put_bucket_website(
                Bucket=dom,
                WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}, "ErrorDocument": {"Key": "index.html"}},
            )
            html_body = f"<!DOCTYPE html><html><head><title>{dom}</title></head><body><h1>Welcome to {dom}</h1><p>Contact: support@{dom}</p></body></html>"
            s3.put_object(Bucket=dom, Key="index.html", Body=html_body.encode("utf-8"), ContentType="text/html")

            s3_endpoint = f"{dom}.s3-website-{region}.amazonaws.com" if region != "us-east-1" else f"{dom}.s3-website-us-east-1.amazonaws.com"
            if zone_id:
                manage_dns_record(session, zone_id, root, "replace", "CNAME", "@", s3_endpoint, proxied=True)
                if add_www_cname == "true":
                    manage_dns_record(session, zone_id, root, "replace", "CNAME", "www", dom, proxied=True)
                if set_flexible_ssl == "true":
                    session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", json={"value": "flexible"}, timeout=TIMEOUT)
                if always_https == "true":
                    session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/always_use_https", json={"value": "on"}, timeout=TIMEOUT)

            extra = "Deployed"
            if verify_after_deploy == "true":
                try:
                    vr = SHARED_HTTP.get(f"https://{dom}", timeout=6)
                    extra = f"HTTP {vr.status_code}"
                except Exception:
                    extra = "Propagating"

            if delay_sec > 0:
                time.sleep(delay_sec)

            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": s3_endpoint, "result": "Deployed S3 & CF CNAME", "extra": extra, "ok": True}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": "S3 Deploy", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 9: GOOGLE POSTMASTER BULK VERIFY & DNS
# ==========================================
@app.post("/api/bulk-postmaster")
async def bulk_postmaster(
    request: Request,
    domains_text: str = Form(""),
    pm_mode: str = Form("google_api_auto"),
    google_oauth_token: str = Form(""),
    manual_txt_token: str = Form(""),
    propagation_wait: int = Form(1),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    g_token = google_oauth_token.strip() or DEFAULT_GOOGLE_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()][:MAX_DOMAINS_PER_RUN]
    session = create_session(cf_token)
    cache = {}
    wait_sec = max(0, min(int(propagation_wait or 0), 10))

    def work(idx: int, total: int, dom: str) -> dict:
        root, sub = extract_root_and_sub(dom)
        acc = "-"
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": dom, "account": "-", "target": f"TXT ({sub})", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            if pm_mode == "manual_txt":
                if not manual_txt_token.strip():
                    return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": "Missing Manual Google TXT Token", "extra": "-", "ok": False}
                ok, msg = manage_dns_record(session, zone_id, root, "add_if_missing", "TXT", sub, manual_txt_token.strip(), proxied=False)
                return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": msg, "extra": "-", "ok": ok}

            if not g_token:
                return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": "Missing Google OAuth Access Token", "extra": "-", "ok": False}

            g_headers = {"Authorization": f"Bearer {g_token}", "Content-Type": "application/json"}
            client = build_resilient_session(g_headers)

            v2_create_resp = client.post(
                "https://gmailpostmastertools.googleapis.com/v2/domains",
                params={"domainId": dom},
                json={},
                timeout=TIMEOUT,
            )
            if v2_create_resp.status_code == 400:
                v2_create_resp = client.post(
                    "https://gmailpostmastertools.googleapis.com/v2/domains",
                    json={"domainName": dom},
                    timeout=TIMEOUT,
                )

            v2_create = v2_create_resp.json() if v2_create_resp.text else {}
            v2_ok = (v2_create_resp.status_code in (200, 201, 409)) or ("name" in v2_create)
            v2_err_reason = v2_create.get("error", {}).get("message") or f"Postmaster HTTP {v2_create_resp.status_code}"

            txt_tok = v2_create.get("verificationToken") or ""
            current_state = str(v2_create.get("verificationState") or v2_create.get("permission") or "").upper()

            if v2_ok and not txt_tok:
                dom_info_resp = client.get(f"https://gmailpostmastertools.googleapis.com/v2/domains/{dom}", timeout=TIMEOUT)
                if dom_info_resp.text:
                    dom_info = dom_info_resp.json()
                    txt_tok = dom_info.get("verificationToken") or ""
                    current_state = str(dom_info.get("verificationState") or dom_info.get("permission") or current_state).upper()

            if not txt_tok:
                tr_resp = client.post(
                    "https://www.googleapis.com/siteVerification/v1/token",
                    json={"verificationMethod": "DNS_TXT", "site": {"type": "INET_DOMAIN", "identifier": dom}},
                    timeout=TIMEOUT,
                )
                tr = tr_resp.json() if tr_resp.text else {}
                txt_tok = tr.get("token", "")
                if not txt_tok and not v2_ok:
                    sv_err = tr.get("error", {}).get("message")
                    if sv_err:
                        v2_err_reason = f"{v2_err_reason} | SiteVer: {sv_err}"

            if not txt_tok:
                return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": v2_err_reason, "extra": "-", "ok": False}

            dns_ok, dns_msg = manage_dns_record(session, zone_id, root, "add_if_missing", "TXT", sub, txt_tok, proxied=False)
            if sub != "@":
                manage_dns_record(session, zone_id, root, "add_if_missing", "TXT", "@", txt_tok, proxied=False)

            if not dns_ok:
                return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": f"DNS TXT Failed: {dns_msg}", "extra": "-", "ok": False}

            if wait_sec > 0:
                time.sleep(wait_sec)

            v_ok = current_state in ("VERIFIED", "OWNER", "TENANT")
            v2_verified = v_ok
            err_msg = "Verification Pending"

            if v2_ok and not v2_verified:
                v2_ver_resp = client.post(f"https://gmailpostmastertools.googleapis.com/v2/domains/{dom}:verify", json={}, timeout=TIMEOUT)
                v2_ver = v2_ver_resp.json() if v2_ver_resp.text else {}
                if v2_ver_resp.status_code in (200, 204) and "error" not in v2_ver:
                    v2_verified = True
                    v_ok = True
                else:
                    err_msg = v2_ver.get("error", {}).get("message") or f"v2 Verify HTTP {v2_ver_resp.status_code}"

            vr_resp = client.post(
                "https://www.googleapis.com/siteVerification/v1/webResource?verificationMethod=DNS_TXT",
                json={"site": {"type": "INET_DOMAIN", "identifier": dom}},
                timeout=TIMEOUT,
            )
            vr = vr_resp.json() if vr_resp.text else {}
            if "id" in vr:
                v_ok = True
            elif not v_ok:
                err_msg = vr.get("error", {}).get("message") or err_msg

            if v2_ok and v2_verified:
                ui_tag, extra_tag = "Verified & Added to Postmaster UI", "Postmaster UI + DNS Verified"
            elif v2_ok and v_ok:
                ui_tag, extra_tag = "Added to UI (SiteVerified — Click Verify in UI if Unverified)", "SiteVerified (Check UI)"
            elif v2_ok:
                ui_tag, extra_tag = f"Added to UI ({err_msg})", "Pending UI Verify"
            else:
                ui_tag, extra_tag = f"SiteVerified ({v2_err_reason[:45]})", "DNS Verified"

            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": ui_tag if v_ok else err_msg, "extra": extra_tag, "ok": v_ok}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": f"TXT ({sub})", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 10: YAHOO SENDER HUB BULK VERIFY & DNS
# ==========================================
def parse_yahoo_cookie_and_csrf(raw_cookie: str, raw_csrf: str = ""):
    y_cookie = (raw_cookie or "").strip() or DEFAULT_YAHOO_COOKIE
    extracted_csrf = (raw_csrf or "").strip()
    if not extracted_csrf and "__Host-senders.x-csrf-token=" in y_cookie:
        try:
            tok_part = y_cookie.split("__Host-senders.x-csrf-token=", 1)[1].split(";", 1)[0].strip()
            extracted_csrf = tok_part.split("%7C")[0].split("|")[0]
        except Exception:
            pass
    headers = {
        "Cookie": y_cookie,
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Origin": "https://senders.yahooinc.com",
        "Referer": "https://senders.yahooinc.com/feature-management/account-overview/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
    }
    if extracted_csrf:
        headers["x-csrf-token"] = extracted_csrf
    return y_cookie, headers


@app.post("/api/yahoo-fetch-unverified")
async def yahoo_fetch_unverified(yahoo_cookie: str = Form("")):
    y_cookie, y_headers = parse_yahoo_cookie_and_csrf(yahoo_cookie)
    if not y_cookie:
        return {"ok": False, "error": "Paste your Yahoo Session Cookie first."}

    try:
        r = SHARED_HTTP.get("https://senders.yahooinc.com/api/v1/domains", headers=y_headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"ok": False, "error": f"Session expired or invalid (HTTP {r.status_code})"}

        payload = r.json()
        items = payload if isinstance(payload, list) else payload.get("domains") or payload.get("data") or []

        total_count = 0
        unverified_pairs = []
        seen_roots = set()

        for item in items:
            d_name = (item.get("domain") or item.get("name") or "").strip().lower()
            if not d_name:
                continue
            root_domain, _ = extract_root_and_sub(d_name)
            total_count += 1

            status = str(item.get("status") or item.get("verificationStatus") or "").upper()
            is_verified = item.get("verified") is True or status in ("VERIFIED", "ACTIVE", "APPROVED")
            raw_tok = (item.get("verificationToken") or item.get("verification_token") or item.get("token") or "").strip()

            if not is_verified and root_domain not in seen_roots:
                seen_roots.add(root_domain)
                if raw_tok and not raw_tok.startswith("yahoo-verification-key="):
                    raw_tok = f"yahoo-verification-key={raw_tok}"
                unverified_pairs.append(f"{root_domain},{raw_tok}" if raw_tok else root_domain)

        return {
            "ok": True,
            "total": total_count,
            "unverified_count": len(unverified_pairs),
            "pairs_text": "\n".join(unverified_pairs[:MAX_DOMAINS_PER_RUN]),
        }
    except Exception as e:
        return {"ok": False, "error": f"Request failed: {str(e)[:80]}"}


@app.post("/api/bulk-yahoo-senderhub")
async def bulk_yahoo_senderhub(
    request: Request,
    domains_text: str = Form(""),
    yahoo_csv: UploadFile = File(None),
    ysh_mode: str = Form("token_pairs"),
    yahoo_cookie: str = Form(""),
    yahoo_csrf: str = Form(""),
    propagation_wait: int = Form(1),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    y_cookie, y_headers = parse_yahoo_cookie_and_csrf(yahoo_cookie, yahoo_csrf)
    raw_entries = []
    if yahoo_csv and yahoo_csv.filename:
        raw = (await yahoo_csv.read()).decode("utf-8-sig")
        for row in csv.reader(io.StringIO(raw)):
            if not row or not row[0].strip():
                continue
            col0 = row[0].strip().lower()
            col1 = row[1].strip() if len(row) > 1 else ""
            if col0 in ("domain", "domains", "subdomain", "subdomains", "host", "hostname", "url"):
                continue
            raw_entries.append((col0, col1))

    for line in domains_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "," in line or "\t" in line:
            parts = [p.strip() for p in line.replace("\t", ",").split(",", 1)]
            raw_entries.append((parts[0].lower(), parts[1]))
        else:
            raw_entries.append((line.lower(), ""))

    entries = []
    seen_roots = {}
    for host, tok in raw_entries[:MAX_DOMAINS_PER_RUN]:
        root_domain, _ = extract_root_and_sub(host)
        if not root_domain:
            continue
        if root_domain not in seen_roots:
            seen_roots[root_domain] = len(entries)
            entries.append([root_domain, tok])
        elif tok and not entries[seen_roots[root_domain]][1]:
            entries[seen_roots[root_domain]][1] = tok

    if not entries:
        async def empty_stream():
            yield f"data: {json.dumps({'error': 'Provide at least one domain (or upload a CSV)'})}\n\n"
        return sse_response(empty_stream())

    cf_session = create_session(cf_token)
    cache = {}
    wait_sec = max(0, min(int(propagation_wait or 0), 10))
    yahoo_map = {}
    if y_cookie:
        try:
            r = SHARED_HTTP.get("https://senders.yahooinc.com/api/v1/domains", headers=y_headers, timeout=TIMEOUT)
            if r.status_code == 200:
                payload = r.json()
                items = payload if isinstance(payload, list) else payload.get("domains") or payload.get("data") or []
                for item in items:
                    d_name = (item.get("domain") or item.get("name") or "").strip().lower()
                    d_id = item.get("id") or item.get("uuid") or item.get("domainId")
                    d_tok = item.get("verificationToken") or item.get("verification_token") or item.get("token") or ""
                    if d_name:
                        root_d, _ = extract_root_and_sub(d_name)
                        yahoo_map[root_d] = {"id": d_id, "token": d_tok}
        except Exception:
            pass

    def work(idx: int, total: int, pair: list) -> dict:
        root_domain, provided_token = pair[0], pair[1]
        try:
            zone_id, account = get_zone_cached(cf_session, root_domain, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": root_domain, "account": "-", "target": "TXT (@)", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            txt_value = (provided_token or "").strip() or yahoo_map.get(root_domain, {}).get("token", "").strip()
            if txt_value and not txt_value.startswith("yahoo-verification-key="):
                txt_value = f"yahoo-verification-key={txt_value}"

            if not txt_value:
                return {"index": idx, "total": total, "domain": root_domain, "account": account, "target": "TXT (@)", "result": "Missing yahoo-verification-key token", "extra": "-", "ok": False}

            dns_ok, dns_msg = manage_dns_record(cf_session, zone_id, root_domain, "add_if_missing", "TXT", "@", txt_value, proxied=False)
            if not dns_ok:
                return {"index": idx, "total": total, "domain": root_domain, "account": account, "target": "TXT (@)", "result": dns_msg, "extra": "-", "ok": False}

            if wait_sec > 0:
                time.sleep(wait_sec)

            if y_cookie:
                domain_uuid = yahoo_map.get(root_domain, {}).get("id")
                if not domain_uuid:
                    return {"index": idx, "total": total, "domain": root_domain, "account": account, "target": "TXT (@)", "result": f"{dns_msg} (Domain UUID not found in YSH)", "extra": "DNS Added", "ok": False}

                ver_resp = SHARED_HTTP.patch("https://senders.yahooinc.com/api/v1/domains", headers=y_headers, json={"domains": [domain_uuid]}, timeout=TIMEOUT)
                if ver_resp.status_code in (200, 202, 204, 207):
                    return {"index": idx, "total": total, "domain": root_domain, "account": account, "target": "TXT (@)", "result": f"{dns_msg} → Verified in Yahoo Sender Hub", "extra": "Verified", "ok": True}
                return {"index": idx, "total": total, "domain": root_domain, "account": account, "target": "TXT (@)", "result": f"{dns_msg} (Auto-Verify HTTP {ver_resp.status_code})", "extra": "DNS Added", "ok": False}

            return {"index": idx, "total": total, "domain": root_domain, "account": account, "target": "TXT (@)", "result": f"{dns_msg} → {txt_value}", "extra": "DNS Added", "ok": True}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": root_domain, "account": "-", "target": "Yahoo Sender Hub", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, entries, work, concurrency=6))


# ==========================================
# TAB 11: AMAZON SES BULK VERIFY & CF DNS
# ==========================================
def format_cf_txt(val: str) -> str:
    clean = val.strip().strip('"').strip()
    return f'"{clean}"'


def merge_spf_record(cf_session, zone_id: str, root_domain: str, rel_name: str, include_domain: str = "amazonses.com"):
    clean_root = root_domain.strip().rstrip(".").lower()
    clean_rel = rel_name.strip().rstrip(".").lower()
    if clean_rel in ("@", "", clean_root):
        fqdn = clean_root
    elif clean_rel.endswith(f".{clean_root}"):
        fqdn = clean_rel
    else:
        fqdn = f"{clean_rel}.{clean_root}"

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    include_token = f"include:{include_domain}"

    try:
        r = cf_session.get(url, params={"type": "TXT", "name": fqdn, "per_page": 100}, timeout=TIMEOUT).json()
        all_txt = r.get("result", []) if r.get("success") else []
        spf_records = [
            (rec, rec.get("content", "").replace('" "', "").strip().strip('"').strip())
            for rec in all_txt
            if rec.get("name", "").strip().rstrip(".").lower() == fqdn
            and rec.get("content", "").replace('" "', "").strip().strip('"').strip().lower().startswith("v=spf1")
        ]

        if not spf_records:
            cr = cf_session.post(url, json={"type": "TXT", "name": fqdn, "content": format_cf_txt(f"v=spf1 {include_token} ~all"), "ttl": 1, "proxied": False}, timeout=TIMEOUT).json()
            if cr.get("success"):
                return True, "SPF Created"
            return False, (cr.get("errors") or [{}])[0].get("message", "SPF create failed")

        primary_rec, existing_val = spf_records[0]
        deduped, seen_tokens = [], set()
        for p in existing_val.split():
            if p.lower() not in seen_tokens:
                seen_tokens.add(p.lower())
                deduped.append(p)

        if any(p.lower() == include_token.lower() for p in deduped):
            return True, "SPF Verified"

        qualifiers = ("-all", "~all", "?all", "+all", "all")
        if deduped and deduped[-1].lower() in qualifiers:
            deduped.insert(len(deduped) - 1, include_token)
        else:
            deduped.append(include_token)

        upd = cf_session.put(
            f"{url}/{primary_rec['id']}",
            json={"type": "TXT", "name": fqdn, "content": format_cf_txt(" ".join(deduped)), "ttl": primary_rec.get("ttl", 1), "proxied": False},
            timeout=TIMEOUT,
        ).json()
        if upd.get("success"):
            return True, "SPF Merged"
        return False, (upd.get("errors") or [{}])[0].get("message", "SPF merge failed")
    except Exception as e:
        return False, str(e)[:60]


def ensure_single_dmarc(cf_session, zone_id: str, root_domain: str, dmarc_rel: str, dmarc_val: str):
    clean_root = root_domain.strip().rstrip(".").lower()
    clean_rel = dmarc_rel.strip().rstrip(".").lower()
    fqdn = clean_rel if clean_rel.endswith(f".{clean_root}") else f"{clean_rel}.{clean_root}"
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"

    try:
        r = cf_session.get(url, params={"type": "TXT", "name": fqdn, "per_page": 100}, timeout=TIMEOUT).json()
        for rec in (r.get("result", []) if r.get("success") else []):
            raw_c = rec.get("content", "").replace('" "', "").strip().strip('"').strip()
            if rec.get("name", "").strip().rstrip(".").lower() == fqdn and raw_c.lower().startswith("v=dmarc1"):
                return True, "DMARC Exists"

        cr = cf_session.post(url, json={"type": "TXT", "name": fqdn, "content": format_cf_txt(dmarc_val), "ttl": 1, "proxied": False}, timeout=TIMEOUT).json()
        if cr.get("success"):
            return True, "DMARC Created"
        return False, (cr.get("errors") or [{}])[0].get("message", "DMARC create failed")
    except Exception as e:
        return False, str(e)[:60]


@app.post("/api/bulk-ses-verify")
async def bulk_ses_verify(
    request: Request,
    domains_text: str = Form(""),
    ses_mode: str = Form("enroll_and_verify"),
    aws_access_key: str = Form(""),
    aws_secret_key: str = Form(""),
    aws_region: str = Form("us-east-1"),
    enable_mail_from: str = Form(""),
    mail_from_sub: str = Form("mail"),
    add_root_spf: str = Form(""),
    add_ses_dmarc: str = Form(""),
    dmarc_policy: str = Form("none"),
    dmarc_rua: str = Form(""),
    config_set_name: str = Form(""),
    sns_topic_arn: str = Form(""),
    poll_seconds: int = Form(0),
    api_token: str = Form(""),
):
    cf_token = api_token.strip() or DEFAULT_TOKEN
    ak = aws_access_key.strip() or DEFAULT_AWS_KEY
    sk = aws_secret_key.strip() or DEFAULT_AWS_SECRET
    if (not cf_token and ses_mode == "enroll_and_verify") or not ak or not sk:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare Token or AWS SES Credentials'})}\n\n"
        return sse_response(err_stream())

    region = aws_region.strip() or "us-east-1"
    raw_domains = [line.strip().lower() for line in domains_text.splitlines() if line.strip()]
    seen, domains = set(), []
    for d in raw_domains:
        if d not in seen:
            seen.add(d)
            domains.append(d)
    domains = domains[:MAX_DOMAINS_PER_RUN]

    ses = boto3.client("sesv2", region_name=region, aws_access_key_id=ak, aws_secret_access_key=sk)
    ses_v1 = boto3.client("ses", region_name=region, aws_access_key_id=ak, aws_secret_access_key=sk)
    acc_info = ses.get_account()
    prod_label = "Production" if acc_info.get("ProductionAccessEnabled") else "Sandbox"
    cf_session = create_session(cf_token) if cf_token else None
    cache = {}

    def work(idx: int, total: int, host: str) -> dict:
        root_domain, _ = extract_root_and_sub(host)
        try:
            if ses_mode == "check_status":
                try:
                    check = ses.get_email_identity(EmailIdentity=host)
                    verified = bool(check.get("VerifiedForSendingStatus"))
                    dkim_status = check.get("DkimAttributes", {}).get("Status", "UNKNOWN")
                    mf_domain = check.get("MailFromAttributes", {}).get("MailFromDomain", "-")
                    return {
                        "index": idx, "total": total, "domain": host, "account": f"AWS SES ({prod_label})",
                        "target": f"{region} • MAIL FROM: {mf_domain}",
                        "result": "Verified & Ready for Sending" if verified else f"Not Verified (DKIM: {dkim_status})",
                        "extra": f"DKIM: {dkim_status}", "ok": verified,
                    }
                except Exception:
                    return {"index": idx, "total": total, "domain": host, "account": f"AWS SES ({prod_label})", "target": region, "result": "Not Enrolled in This SES Region", "extra": "-", "ok": False}

            zone_id, account = get_zone_cached(cf_session, root_domain, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": host, "account": "-", "target": f"SES ({region})", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            create_kwargs = {"EmailIdentity": host}
            if config_set_name.strip():
                create_kwargs["ConfigurationSetName"] = config_set_name.strip()

            try:
                resp = ses.create_email_identity(**create_kwargs)
            except ses.exceptions.AlreadyExistsException:
                resp = ses.get_email_identity(EmailIdentity=host)

            dkim_tokens = resp.get("DkimAttributes", {}).get("Tokens", []) or ses.get_email_identity(EmailIdentity=host).get("DkimAttributes", {}).get("Tokens", [])
            if not dkim_tokens:
                return {"index": idx, "total": total, "domain": host, "account": account, "target": f"SES ({region})", "result": "No DKIM tokens returned by AWS SES", "extra": "-", "ok": False}

            cf_dns_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            dkim_added, dkim_errors = 0, []
            for tok in dkim_tokens:
                fqdn_cname = f"{tok}._domainkey.{host}".lower()
                target_cname = f"{tok}.dkim.amazonses.com"
                c_resp = cf_session.post(cf_dns_url, json={"type": "CNAME", "name": fqdn_cname, "content": target_cname, "ttl": 1, "proxied": False}, timeout=TIMEOUT).json()
                if c_resp.get("success"):
                    dkim_added += 1
                else:
                    err_msg = (c_resp.get("errors") or [{}])[0].get("message", "CNAME failed")
                    if "already exists" in err_msg.lower() or "identical" in err_msg.lower():
                        dkim_added += 1
                    else:
                        dkim_errors.append(err_msg)

            if dkim_added < 3:
                return {"index": idx, "total": total, "domain": host, "account": account, "target": f"SES ({region})", "result": f"DKIM CNAME Error ({dkim_added}/3): {', '.join(dkim_errors)}", "extra": "Check CF Token DNS Edit Permission", "ok": False}

            records_summary = [f"{dkim_added}/3 DKIM CNAME"]
            mf_clean = mail_from_sub.strip().strip(".")
            if enable_mail_from == "true" and mf_clean:
                mf_fqdn = f"{mf_clean}.{host}"
                try:
                    ses.put_email_identity_mail_from_attributes(EmailIdentity=host, MailFromDomain=mf_fqdn, BehaviorOnMxFailure="USE_DEFAULT_VALUE")
                    mf_rel = mf_fqdn if mf_fqdn == root_domain else mf_fqdn.replace("." + root_domain, "")
                    manage_dns_record(cf_session, zone_id, root_domain, "replace", "MX", mf_rel, f"feedback-smtp.{region}.amazonses.com", proxied=False, priority=10)
                    merge_spf_record(cf_session, zone_id, root_domain, mf_rel, "amazonses.com")
                    records_summary.append(f"MAIL FROM ({mf_clean})")
                except Exception:
                    pass

            if add_root_spf == "true":
                root_rel = "@" if host == root_domain else host.replace("." + root_domain, "")
                ok_spf, spf_note = merge_spf_record(cf_session, zone_id, root_domain, root_rel, "amazonses.com")
                if ok_spf:
                    records_summary.append(spf_note)

            if add_ses_dmarc == "true":
                dmarc_rel = "_dmarc" if host == root_domain else f"_dmarc.{host.replace('.' + root_domain, '')}"
                rua_clean = dmarc_rua.strip()
                if rua_clean and not rua_clean.startswith("mailto:"):
                    rua_clean = f"mailto:{rua_clean}"
                dmarc_val = f"v=DMARC1; p={dmarc_policy}; rua={rua_clean};" if rua_clean else f"v=DMARC1; p={dmarc_policy};"
                ok_dmarc, dmarc_note = ensure_single_dmarc(cf_session, zone_id, root_domain, dmarc_rel, dmarc_val)
                if ok_dmarc:
                    records_summary.append(dmarc_note)

            topic = sns_topic_arn.strip()
            if topic:
                try:
                    ses_v1.set_identity_notification_topic(Identity=host, NotificationType="Bounce", SnsTopic=topic)
                    ses_v1.set_identity_notification_topic(Identity=host, NotificationType="Complaint", SnsTopic=topic)
                    ses_v1.set_identity_feedback_forwarding_enabled(Identity=host, ForwardingEnabled=False)
                    records_summary.append("SNS Feedback")
                except Exception:
                    pass

            check = ses.get_email_identity(EmailIdentity=host)
            verified = bool(check.get("VerifiedForSendingStatus"))
            dkim_status = check.get("DkimAttributes", {}).get("Status", "PENDING")

            return {
                "index": idx, "total": total, "domain": host, "account": account,
                "target": f"SES ({region} • {prod_label}) • {' + '.join(records_summary)}",
                "result": "Verified & Ready for Sending (SES)" if verified else f"Records Added — SES Status: {dkim_status}",
                "extra": f"DKIM: {dkim_status}", "ok": True,
            }
        except Exception as exc:
            return {"index": idx, "total": total, "domain": host, "account": "-", "target": f"SES ({region})", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))