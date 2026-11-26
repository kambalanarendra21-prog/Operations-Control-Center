import os
import io
import csv
import hmac
import html
import json
import re
import time
import hashlib
import secrets
import sqlite3
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
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

AUTH_SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", "occ-super-secret-signing-key-change-me").strip()
DEFAULT_SUPER_ADMIN_USER = os.environ.get("SUPER_ADMIN_USER", "admin").strip()
DEFAULT_SUPER_ADMIN_PASS = os.environ.get("SUPER_ADMIN_PASS", "Admin@12345").strip()
SESSION_COOKIE_NAME = "occ_session"

ALL_WORKSPACE_TABS = [
    "dns", "csv", "ssl", "redir", "prov", "audit",
    "dyna", "s3", "pm", "ysh", "ses", "jobs", "guide", "convert"
]

DEFAULT_ADMIN_USER = {
    "id": 1,
    "username": DEFAULT_SUPER_ADMIN_USER.lower() or "admin",
    "display_name": "Super Admin",
    "role": "super_admin",
    "allowed_tabs": list(ALL_WORKSPACE_TABS),
    "tab_levels": {t: "full" for t in ALL_WORKSPACE_TABS},
    "is_active": True,
}

TIMEOUT = 25
DB_PATH = "jobs.db"


# ==========================================
# PASSWORD HASHING & SIGNED SESSION HELPERS
# ==========================================
def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt_hex = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 120_000)
    return f"{salt_hex}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hex = stored_hash.split("$", 1)
        candidate = hash_password(password, salt_hex)
        return hmac.compare_digest(candidate, f"{salt_hex}${expected_hex}")
    except Exception:
        return False


def create_session_token(user_id: int, username: str, role: str) -> str:
    exp = int(time.time()) + (7 * 24 * 3600)
    payload = f"{user_id}:{username}:{role}:{exp}"
    sig = hmac.new(AUTH_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> Optional[dict]:
    if not token:
        return None
    try:
        parts = token.split(":")
        if len(parts) != 5:
            return None
        uid_s, username, role, exp_s, sig = parts
        payload = f"{uid_s}:{username}:{role}:{exp_s}"
        expected_sig = hmac.new(AUTH_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        if int(exp_s) < int(time.time()):
            return None
        return {"id": int(uid_s), "username": username, "role": role}
    except Exception:
        return None


# ==========================================
# SQLITE PERSISTENT JOB QUEUE, RBAC & KEYS
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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'sub_account',
            allowed_tabs_json TEXT NOT NULL DEFAULT '[]',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            service TEXT NOT NULL,
            secret_json TEXT NOT NULL,
            assigned_users_json TEXT NOT NULL DEFAULT '[]',
            created_by INTEGER,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            actor_username TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)

    existing_super = conn.execute("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1").fetchone()
    if not existing_super:
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash, role, allowed_tabs_json, is_active, created_at) VALUES (?, ?, ?, 'super_admin', ?, 1, ?)",
            (
                DEFAULT_SUPER_ADMIN_USER.lower(),
                "Super Admin",
                hash_password(DEFAULT_SUPER_ADMIN_PASS),
                json.dumps({t: "full" for t in ALL_WORKSPACE_TABS}),
                datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
            ),
        )

    conn.commit()
    conn.close()


init_db()


def log_activity(user: Optional[dict], action: str, target_type: str = "system", target_id: str = "-", details: str = ""):
    actor_u = (user or {}).get("username") or DEFAULT_ADMIN_USER["username"]
    actor_r = (user or {}).get("role") or "super_admin"
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO activity_logs (created_at, actor_username, actor_role, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
                actor_u,
                actor_r,
                action,
                target_type,
                str(target_id),
                str(details)[:300],
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_current_user(request: Request) -> Optional[dict]:
    return dict(DEFAULT_ADMIN_USER)


def check_tab_permission(
    request: Request,
    required_tab: Optional[str] = None,
    super_only: bool = False,
    require_write: bool = False,
) -> Tuple[Optional[dict], Optional[str]]:
    return dict(DEFAULT_ADMIN_USER), None


def resolve_saved_key_secret(user: dict, service: str, key_id: str, fallback_fields: dict) -> Tuple[dict, Optional[str]]:
    kid = (key_id or "").strip()
    if not kid:
        return fallback_fields, None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id, label, service, secret_json FROM saved_keys WHERE id = ?", (int(kid),)).fetchone()
    conn.close()
    if not row:
        return fallback_fields, None
    return json.loads(row["secret_json"] or "{}"), None


def unauthorized_sse(message: str, status_code: int = 403):
    async def err_stream():
        yield f"data: {json.dumps({'error': message})}\n\n"
    return StreamingResponse(
        err_stream(),
        status_code=status_code,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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


def format_cf_txt(val: str) -> str:
    clean = val.strip().strip('"').strip()
    return f'"{clean}"'


def _normalize_txt_content(raw: str) -> str:
    s = (raw or "").strip()
    s = re.sub(r'"\s+"', " ", s)
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    s = s.replace('\\"', '"').strip()
    return re.sub(r"\s+", " ", s)


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
                if content and content.strip() and _normalize_txt_content(rec.get("content", "")) != _normalize_txt_content(content):
                    continue
                dr = session.delete(f"{url}/{rec['id']}", timeout=TIMEOUT).json()
                if dr.get("success"):
                    deleted += 1
            return True, f"Deleted {deleted} {rtype_up} ({name})"

        if action == "add_if_missing":
            for rec in existing:
                if not content or _normalize_txt_content(rec.get("content", "")) == _normalize_txt_content(content):
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


def smart_merge_spf_record(
    cf_session: requests.Session,
    zone_id: str,
    root_domain: str,
    rel_name: str,
    spf_input: str,
    ttl: int = 1,
) -> Tuple[bool, str]:
    clean_root = root_domain.strip().rstrip(".").lower()
    clean_rel = (rel_name or "@").strip().rstrip(".").lower()
    if clean_rel in ("@", "", clean_root):
        fqdn = clean_root
    elif clean_rel.endswith(f".{clean_root}"):
        fqdn = clean_rel
    else:
        fqdn = f"{clean_rel}.{clean_root}"

    raw_spf = _normalize_txt_content(spf_input)
    if not raw_spf:
        return False, "Empty SPF content"

    qualifiers = ("-all", "~all", "?all", "+all", "all")
    incoming_tokens = [t for t in raw_spf.split() if t.lower() != "v=spf1"]
    incoming_qual = next((t for t in reversed(incoming_tokens) if t.lower() in qualifiers), None)
    incoming_terms = [t for t in incoming_tokens if t.lower() not in qualifiers]

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    try:
        r = cf_session.get(url, params={"type": "TXT", "name": fqdn, "per_page": 100}, timeout=TIMEOUT).json()
        all_txt = r.get("result", []) if r.get("success") else []

        spf_records = []
        for rec in all_txt:
            rec_fqdn = rec.get("name", "").strip().rstrip(".").lower()
            norm_c = _normalize_txt_content(rec.get("content", ""))
            if rec_fqdn == fqdn and ("v=spf1" in norm_c.lower() or norm_c.lower().startswith("spf1")):
                spf_records.append((rec, norm_c))

        if not spf_records:
            final_qual = incoming_qual or "~all"
            new_val = " ".join(["v=spf1"] + incoming_terms + [final_qual])
            cr = cf_session.post(
                url,
                json={
                    "type": "TXT",
                    "name": fqdn,
                    "content": format_cf_txt(new_val),
                    "ttl": int(ttl) if ttl else 1,
                    "proxied": False,
                },
                timeout=TIMEOUT,
            ).json()
            if cr.get("success"):
                return True, f"SPF Created ({fqdn}): {new_val}"
            return False, (cr.get("errors") or [{}])[0].get("message", "SPF create failed")

        merged_terms = []
        seen_lower = set()
        existing_qual = None

        for _, ex_val in spf_records:
            parts = ex_val.split()
            for tok in parts:
                low = tok.lower()
                if low == "v=spf1":
                    continue
                if low in qualifiers:
                    if not existing_qual:
                        existing_qual = tok
                    continue
                if low not in seen_lower:
                    seen_lower.add(low)
                    merged_terms.append(tok)

        added_new = False
        for term in incoming_terms:
            low = term.lower()
            if low not in seen_lower:
                seen_lower.add(low)
                merged_terms.append(term)
                added_new = True

        final_qual = existing_qual or incoming_qual or "~all"
        merged_val = " ".join(["v=spf1"] + merged_terms + [final_qual])

        primary_rec, first_existing_val = spf_records[0]
        duplicates_removed = 0
        for extra_rec, _ in spf_records[1:]:
            try:
                dr = cf_session.delete(f"{url}/{extra_rec['id']}", timeout=TIMEOUT).json()
                if dr.get("success"):
                    duplicates_removed += 1
            except Exception:
                pass

        if not added_new and duplicates_removed == 0 and merged_val == first_existing_val:
            return True, f"SPF Already Merged ({fqdn}): {merged_val}"

        upd = cf_session.put(
            f"{url}/{primary_rec['id']}",
            json={
                "type": "TXT",
                "name": fqdn,
                "content": format_cf_txt(merged_val),
                "ttl": primary_rec.get("ttl", int(ttl) if ttl else 1),
                "proxied": False,
            },
            timeout=TIMEOUT,
        ).json()
        if upd.get("success"):
            dup_note = f" + Removed {duplicates_removed} Dup SPF" if duplicates_removed else ""
            return True, f"SPF Merged ({fqdn}){dup_note}: {merged_val}"
        return False, (upd.get("errors") or [{}])[0].get("message", "SPF merge failed")
    except Exception as e:
        return False, str(e)[:80]


def _apply_optional_csv_ssl(cf_session: requests.Session, zone_id: str, ssl_raw: str) -> str:
    ssl_v = (ssl_raw or "").strip().lower()
    if not ssl_v or ssl_v not in ("off", "flexible", "full", "strict"):
        return "-"
    try:
        sr = cf_session.patch(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl",
            json={"value": ssl_v},
            timeout=TIMEOUT,
        ).json()
        if sr.get("success"):
            return f"SSL: {ssl_v}"
        err_msg = (sr.get("errors") or [{}])[0].get("message", "SSL patch skipped")
        return f"SSL Note: {err_msg[:45]}"
    except Exception as e:
        return f"SSL Note: {str(e)[:45]}"


# ==========================================
# DASHBOARD UI & UTILITY ENDPOINTS
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = dict(DEFAULT_ADMIN_USER)
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
            "is_authenticated": True,
            "current_user_json": json.dumps(user),
        },
    )


@app.get("/sample-csv")
async def sample_csv():
    content = (
        "domain,action,type,name,content,proxied,priority,ttl,ssl_mode\n"
        "example1.com,replace,A,@,3.23.10.37,true,,1,\n"
        "example1.com,merge_spf,TXT,@,v=spf1 include:amazonses.com ~all,false,,1,\n"
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


@app.post("/api/google-token-info")
async def google_token_info(request: Request, google_oauth_token: str = Form(""), google_key_id: str = Form("")):
    user, _ = check_tab_permission(request, required_tab="pm")
    sec, _ = resolve_saved_key_secret(user, "google", google_key_id, {"token": google_oauth_token})
    tok = (sec.get("token") or google_oauth_token or "").strip() or DEFAULT_GOOGLE_TOKEN
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


@app.post("/api/accounts")
async def list_cf_accounts(request: Request, api_token: str = Form(""), cf_key_id: str = Form("")):
    user, _ = check_tab_permission(request)
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not token:
        return {"success": False, "error": "Missing Cloudflare API Token"}
    try:
        s = create_session(token)
        r = s.get("https://api.cloudflare.com/client/v4/accounts", params={"per_page": 50}, timeout=TIMEOUT).json()
        if not r.get("success"):
            err_msg = (r.get("errors") or [{}])[0].get("message", "Failed to load accounts")
            return {"success": False, "error": err_msg}
        accounts = [{"id": a["id"], "name": a["name"]} for a in r.get("result", [])]
        return {"success": True, "accounts": accounts}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==========================================
# TAB 1: BULK DNS (UNLIMITED + DELETE SPECIFIED RECORDS)
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
    specified_delete_json: str = Form("[]"),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="dns", require_write=(dry_run != "true"))
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    cf_token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    is_proxied = proxied == "true"
    is_dry_run = dry_run == "true"
    prio_val = int(priority) if priority.strip().isdigit() else None
    delay_sec = max(0, min(int(request_delay_ms or 0), 5000)) / 1000.0
    try:
        spec_rules = [r for r in json.loads(specified_delete_json or "[]") if (r.get("type") or "").strip()]
    except Exception:
        spec_rules = []

    if action == "delete_specified" and not spec_rules:
        async def err_spec():
            yield f"data: {json.dumps({'error': 'Add at least one DNS record specification to delete.'})}\n\n"
        return sse_response(err_spec())

    session = create_session(cf_token)
    cache = {}
    log_activity(user, "bulk_dns_run", "domains", str(len(domains)), f"action={action}, type={rtype}, name={name}")

    def work(idx: int, total: int, dom: str) -> dict:
        root, _ = extract_root_and_sub(dom)
        try:
            zone_id, acc = get_zone_cached(session, root, cache)
            if not zone_id:
                return {"index": idx, "total": total, "domain": dom, "account": "-", "target": f"{rtype} ({name})", "result": "CF Zone Not Found", "extra": "-", "ok": False}

            if action == "delete_specified":
                target_label = ", ".join(f"{r.get('type','').upper()} {r.get('name') or '@'}" for r in spec_rules)
                if is_dry_run:
                    return {
                        "index": idx, "total": total, "domain": dom, "account": acc,
                        "target": target_label,
                        "result": f"[DRY-RUN] Would delete {len(spec_rules)} specified rule(s) on {root}",
                        "extra": "Preview Only", "ok": True,
                    }

                results_msgs = []
                all_ok = True
                for rule in spec_rules:
                    r_t = (rule.get("type") or "TXT").strip().upper()
                    r_n = (rule.get("name") or "@").strip().replace("{domain}", root)
                    r_c = (rule.get("content") or "").strip().replace("{domain}", root)
                    ok_r, msg_r = manage_dns_record(session, zone_id, root, "delete", r_t, r_n, r_c)
                    results_msgs.append(msg_r)
                    all_ok = all_ok and ok_r

                if delay_sec > 0:
                    time.sleep(delay_sec)
                return {
                    "index": idx, "total": total, "domain": dom, "account": acc,
                    "target": target_label,
                    "result": " | ".join(results_msgs),
                    "extra": f"{len(spec_rules)} rule(s)",
                    "ok": all_ok,
                }

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
# TAB 2: CSV MULTI-RECORD UPLOAD (UNLIMITED + SMART SPF MERGE)
# ==========================================
@app.post("/api/bulk-csv")
async def bulk_csv(
    request: Request,
    csv_file: UploadFile = File(...),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="csv", require_write=True)
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    cf_token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    raw = (await csv_file.read()).decode("utf-8-sig")
    rows = [r for r in csv.DictReader(io.StringIO(raw)) if (r.get("domain") or "").strip()]
    session = create_session(cf_token)
    cache = {}
    log_activity(user, "bulk_csv_run", "csv_rows", str(len(rows)), csv_file.filename or "upload.csv")

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

            norm_cnt_low = _normalize_txt_content(cnt).lower()
            is_spf_row = (
                rt == "SPF"
                or act in ("merge_spf", "spf_merge")
                or (rt == "TXT" and (norm_cnt_low.startswith("v=spf1") or "v=spf1" in norm_cnt_low))
            )

            if is_spf_row:
                ok, msg = smart_merge_spf_record(session, zone_id, root, nm, cnt, ttl_v)
                display_type = "TXT (SPF)"
            else:
                ok, msg = manage_dns_record(session, zone_id, root, act, rt, nm, cnt, prx, prio, ttl_v)
                display_type = rt

            extra = _apply_optional_csv_ssl(session, zone_id, ssl_v) if ok else "-"

            return {
                "index": idx,
                "total": total,
                "domain": dom,
                "account": acc,
                "target": f"{display_type} ({nm})",
                "result": msg,
                "extra": extra,
                "ok": ok,
            }
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "CSV Row", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, rows, work, concurrency=6))
    # ==========================================
# TAB 3: SSL & CACHE PURGE (UNLIMITED)
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
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="ssl", require_write=True)
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    cf_token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    session = create_session(cf_token)
    cache = {}
    log_activity(user, "bulk_ssl_cache_run", "domains", str(len(domains)), f"ssl={ssl_mode}, purge={purge_cache}")

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
# TAB 4: BULK REDIRECTS (UNLIMITED)
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
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="redir", require_write=True)
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    cf_token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    session = create_session(cf_token)
    cache = {}
    log_activity(user, "bulk_redirect_run", "domains", str(len(domains)), f"preset={redirect_preset}, code={status_code}")

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
# TAB 5: ZONE PROVISIONING & NS FETCHER (UNLIMITED)
# ==========================================
@app.post("/api/bulk-provision")
async def bulk_provision(
    request: Request,
    domains_text: str = Form(""),
    account_id: str = Form(""),
    mode: str = Form("create_and_fetch"),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="prov", require_write=(mode != "fetch_only"))
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    cf_token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    session = create_session(cf_token)
    log_activity(user, "bulk_provision_run", "domains", str(len(domains)), f"mode={mode}")

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

            err_msg = (cr.get("errors") or [{}])[0].get("message", "Create Zone Failed")
            return {"index": idx, "total": total, "domain": root, "account": "-", "target": "Create Zone", "result": err_msg, "extra": "-", "ok": False}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": "-", "target": "Provision", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 6: DNS AUDITOR & BACKUP (UNLIMITED)
# ==========================================
@app.post("/api/bulk-audit")
async def bulk_audit(
    request: Request,
    domains_text: str = Form(""),
    filter_type: str = Form(""),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="audit")
    sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    cf_token = (sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    session = create_session(cf_token)
    cache = {}
    log_activity(user, "bulk_audit_run", "domains", str(len(domains)), f"filter={filter_type or 'ALL'}")

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
# TAB 7: DYNADOT -> CLOUDFLARE MIGRATION (UNLIMITED)
# ==========================================
@app.post("/api/dynadot-sync")
async def dynadot_sync(
    request: Request,
    domains_text: str = Form(""),
    account_id: str = Form(""),
    dynadot_key: str = Form(""),
    dyna_key_id: str = Form(""),
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
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="dyna", require_write=True)
    cf_sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    d_sec, _ = resolve_saved_key_secret(user, "dynadot", dyna_key_id, {"key": dynadot_key})
    cf_token = (cf_sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    d_key = (d_sec.get("key") or dynadot_key or "").strip() or DEFAULT_DYNADOT_KEY
    if not cf_token or not d_key or not account_id:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare Token, Target Account, or Dynadot API Key'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    custom_recs = json.loads(custom_records_json or "[]")
    session = create_session(cf_token)
    log_activity(user, "dynadot_sync_run", "domains", str(len(domains)), f"acc={account_id}")

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
                    err_msg = (cr.get("errors") or [{}])[0].get("message", "Zone Create Failed")
                    return {"index": idx, "total": total, "domain": root, "account": "-", "target": "CF Zone", "result": err_msg, "extra": "-", "ok": False}
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
# S3 WEBSITE GENERATORS (AI PROMPT, REF URL, VERTICAL)
# ==========================================
PALETTES = [
    {"bg": "#0f172a", "surface": "#1e293b", "accent": "#f97316", "text": "#f8fafc", "muted": "#cbd5e1", "hero_grad": "linear-gradient(135deg,#0f172a 0%,#1e293b 100%)"},
    {"bg": "#090d16", "surface": "#131b2e", "accent": "#38bdf8", "text": "#f8fafc", "muted": "#cbd5e1", "hero_grad": "linear-gradient(135deg,#090d16 0%,#0f294a 100%)"},
    {"bg": "#0c1412", "surface": "#152420", "accent": "#10b981", "text": "#f8fafc", "muted": "#d1fae5", "hero_grad": "linear-gradient(135deg,#0c1412 0%,#13382e 100%)"},
    {"bg": "#14110f", "surface": "#26201c", "accent": "#f59e0b", "text": "#fffbeb", "muted": "#fde68a", "hero_grad": "linear-gradient(135deg,#14110f 0%,#362714 100%)"},
    {"bg": "#130f1c", "surface": "#221a33", "accent": "#a855f7", "text": "#faf5ff", "muted": "#e9d5ff", "hero_grad": "linear-gradient(135deg,#130f1c 0%,#2e1b4b 100%)"},
    {"bg": "#f8fafc", "surface": "#ffffff", "accent": "#2563eb", "text": "#0f172a", "muted": "#475569", "hero_grad": "linear-gradient(135deg,#eff6ff 0%,#ffffff 100%)"},
]

VERTICAL_BLUEPRINTS = {
    "finance": {
        "label": "Finance & Lending",
        "tagline": "Structured Capital & Commercial Lending Solutions",
        "lead": "Transparent funding programs, fast underwriting workflows, and dedicated advisory support tailored for growing businesses.",
        "cta": "Explore Funding Options",
        "cards": [
            ("Working Capital Lines", "Flexible revolving credit facilities structured around your operating cash flow and seasonal cycles."),
            ("Equipment & Expansion Financing", "Predictable fixed-term financing to acquire commercial assets without tying up liquid reserves."),
            ("Dedicated Underwriting Desk", "Direct specialist review with clear milestone timelines and straightforward documentation."),
        ],
        "steps": [
            ("1. Initial Assessment", "Share basic operational metrics and funding goals for rapid preliminary sizing."),
            ("2. Structured Terms", "Review transparent rate schedules, repayment terms, and zero-surprise covenants."),
            ("3. Fast Disbursement", "Complete streamlined verification and receive funds directly to your operating account."),
        ],
    },
    "insurance": {
        "label": "Insurance",
        "tagline": "Comprehensive Commercial & Personal Risk Protection",
        "lead": "Tailored policy coverage, proactive risk assessments, and responsive claims advocacy built to protect what matters most.",
        "cta": "Request Coverage Review",
        "cards": [
            ("Commercial Liability & Property", "End-to-end protection for business operations, commercial facilities, and equipment assets."),
            ("Tailored Policy Structuring", "Side-by-side carrier comparisons to eliminate coverage gaps while optimizing annual premiums."),
            ("Responsive Claims Support", "Dedicated policy specialists guiding documentation and resolution from first notice to settlement."),
        ],
        "steps": [
            ("1. Risk Profile Review", "Identify operational exposures, compliance mandates, and existing policy overlaps."),
            ("2. Multi-Carrier Quote", "Compare vetted coverage tiers with transparent deductibles and policy limits."),
            ("3. Active Policy Management", "Instant certificates of insurance and annual renewal optimization."),
        ],
    },
    "tech": {
        "label": "Tech & Software",
        "tagline": "Cloud Infrastructure, Automation & Modern Software Engineering",
        "lead": "Resilient cloud architectures, API integrations, and high-throughput operational software built for modern teams.",
        "cta": "Explore Platform Architecture",
        "cards": [
            ("Cloud-Native Engineering", "Scalable microservices, automated CI/CD pipelines, and fault-tolerant infrastructure deployments."),
            ("Workflow & API Automation", "Connect mission-critical data systems with real-time webhooks, telemetry, and zero-downtime sync."),
            ("Security & Compliance First", "End-to-end encryption, strict access isolation, and continuous observability across environments."),
        ],
        "steps": [
            ("1. Architecture Audit", "Map current system bottlenecks, latency hotspots, and integration requirements."),
            ("2. Modular Deployment", "Ship production-ready components with automated testing and instant rollback safety."),
            ("3. 24/7 Telemetry", "Monitor uptime, throughput, and security posture from a unified operational view."),
        ],
    },
    "healthcare": {
        "label": "Healthcare",
        "tagline": "Patient-Centered Care Coordination & Clinical Services",
        "lead": "Accessible health resources, modern care pathways, and clear patient communication designed for better outcomes.",
        "cta": "View Care Services",
        "cards": [
            ("Preventive & Primary Care", "Comprehensive wellness screenings, chronic condition management, and personalized care plans."),
            ("Streamlined Patient Access", "Clear scheduling, digital intake guidance, and coordinated specialist referrals."),
            ("Evidence-Based Standards", "Clinical protocols grounded in current medical research and compassionate patient support."),
        ],
        "steps": [
            ("1. Care Consultation", "Discuss health history, preventive goals, and diagnostic priorities with our care team."),
            ("2. Personalized Plan", "Receive a structured care roadmap with clear follow-up milestones."),
            ("3. Ongoing Support", "Continuous care coordination and direct portal communication."),
        ],
    },
    "legal": {
        "label": "Legal & Notary",
        "tagline": "Precision Document Execution, Notary & Compliance Services",
        "lead": "Dependable notarization, corporate filings, and structured legal documentation handled with strict confidentiality.",
        "cta": "Schedule Document Review",
        "cards": [
            ("Certified Notary & Apostille", "Accurate verification, witnessing, and authentication for domestic and international documents."),
            ("Corporate & Commercial Filings", "Entity formation records, operating agreements, and regulatory compliance documentation."),
            ("Confidential Handling", "Strict chain-of-custody standards and prompt turnaround for time-sensitive signings."),
        ],
        "steps": [
            ("1. Document Check", "Verify identification requirements, witness rules, and jurisdictional formatting."),
            ("2. Formal Execution", "Complete in-person or scheduled signing with full statutory compliance."),
            ("3. Certified Delivery", "Receive properly sealed originals and digital confirmation records."),
        ],
    },
    "consulting": {
        "label": "Consulting",
        "tagline": "Strategic Operations, Growth & Advisory Consulting",
        "lead": "Actionable operational frameworks, market analysis, and hands-on execution support for measurable business growth.",
        "cta": "Book Strategy Overview",
        "cards": [
            ("Operational Optimization", "Streamline core workflows, reduce overhead, and establish clear KPI accountability."),
            ("Market & Growth Strategy", "Data-backed expansion roadmaps, pricing architecture, and customer acquisition systems."),
            ("Executive Advisory", "Pragmatic guidance from diagnosis through full team implementation."),
        ],
        "steps": [
            ("1. Diagnostic Discovery", "Benchmark current performance, unit economics, and operational bottlenecks."),
            ("2. Roadmap Design", "Prioritize high-leverage initiatives with clear 30-60-90 day milestones."),
            ("3. Guided Execution", "Implement systems alongside your leadership team with measurable tracking."),
        ],
    },
}


def _pick_palette(domain: str) -> dict:
    idx = sum(ord(c) for c in domain.lower()) % len(PALETTES)
    return PALETTES[idx]


def _brand_from_domain(domain: str) -> str:
    root = domain.lower().strip().split(".")[0]
    words = [w.capitalize() for w in re.split(r"[-_]+", root) if w]
    return " ".join(words) if words else domain


def _resolve_vertical_key(domain: str, site_vertical: str) -> str:
    clean_v = (site_vertical or "auto").strip().lower()
    if clean_v in VERTICAL_BLUEPRINTS:
        return clean_v
    d = domain.lower()
    if any(k in d for k in ("fin", "fund", "capital", "wealth", "lend", "loan", "invest", "pay", "bank")):
        return "finance"
    if any(k in d for k in ("insure", "assurance", "cover", "guard", "policy", "shield")):
        return "insurance"
    if any(k in d for k in ("health", "med", "care", "bio", "clinic", "vital", "wellness")):
        return "healthcare"
    if any(k in d for k in ("law", "legal", "notary", "attorney", "advocate", "custody", "trust")):
        return "legal"
    if any(k in d for k in ("tech", "soft", "cloud", "ai", "cyber", "app", "data", "nova", "pulse")):
        return "tech"
    return "consulting"


def _fetch_reference_summary(reference_url: str) -> dict:
    summary = {
        "url": (reference_url or "").strip(),
        "host": "",
        "title": "",
        "description": "",
        "accent_color": "",
        "nav_items": [],
        "headings": [],
        "snippets": [],
    }
    if not summary["url"]:
        return summary
    normalized = summary["url"] if summary["url"].startswith(("http://", "https://")) else f"https://{summary['url']}"
    parsed = urlparse(normalized)
    summary["host"] = parsed.netloc or summary["url"]
    try:
        resp = SHARED_HTTP.get(
            parsed.geturl(),
            timeout=12,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        if resp.ok and resp.text:
            theme_match = re.search(r'<meta[^>]+name=["\']theme-color["\'][^>]+content=["\'](#[0-9a-fA-F]{3,6})["\']', resp.text, flags=re.I)
            if theme_match:
                summary["accent_color"] = theme_match.group(1)
            else:
                hex_colors = re.findall(r"#([0-9a-fA-F]{6})\b", resp.text)
                for hx in hex_colors:
                    if hx.lower() not in ("ffffff", "000000", "f8fafc", "0f172a", "111827", "e2e8f0", "cbd5e1"):
                        summary["accent_color"] = f"#{hx}"
                        break

            raw_html = re.sub(r"<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", resp.text, flags=re.I | re.S)

            title_match = re.search(r"<title[^>]*>(.*?)</title>", raw_html, flags=re.I | re.S)
            if title_match:
                summary["title"] = re.sub(r"\s+", " ", html.unescape(title_match.group(1))).strip()[:120]

            desc_match = re.search(
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
                raw_html,
                flags=re.I | re.S,
            )
            if desc_match:
                summary["description"] = re.sub(r"\s+", " ", html.unescape(desc_match.group(1))).strip()[:240]

            nav_block = re.search(r"<(nav|header)[^>]*>(.*?)</\1>", raw_html, flags=re.I | re.S)
            if nav_block:
                links = re.findall(r"<a[^>]*>(.*?)</a>", nav_block.group(2), flags=re.I | re.S)
                for l in links:
                    txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html.unescape(l))).strip()
                    if 2 <= len(txt) <= 26 and txt.lower() not in [x.lower() for x in summary["nav_items"]]:
                        summary["nav_items"].append(txt)
                summary["nav_items"] = summary["nav_items"][:5]

            h_matches = re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", raw_html, flags=re.I | re.S)
            for h in h_matches:
                txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html.unescape(h))).strip()
                if len(txt) >= 4 and txt.lower() not in [x.lower() for x in summary["headings"]]:
                    summary["headings"].append(txt[:95])
                if len(summary["headings"]) >= 8:
                    break

            p_matches = re.findall(r"<p[^>]*>(.*?)</p>", raw_html, flags=re.I | re.S)
            for p in p_matches:
                txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html.unescape(p))).strip()
                if len(txt) >= 35 and txt not in summary["snippets"]:
                    summary["snippets"].append(txt[:200])
                if len(summary["snippets"]) >= 6:
                    break
    except Exception:
        pass
    return summary


def _render_rich_responsive_html(
    domain: str,
    brand_name: str,
    vertical_label: str,
    headline: str,
    subheadline: str,
    cta_label: str,
    nav_items: list,
    feature_cards: list,
    process_steps: list,
    palette: dict,
) -> str:
    safe_brand = html.escape(brand_name)
    safe_domain = html.escape(domain)
    safe_vertical = html.escape(vertical_label)
    safe_headline = html.escape(headline)
    safe_subheadline = html.escape(subheadline)
    safe_cta = html.escape(cta_label)
    support_email = html.escape(f"support@{domain}")

    nav_links = nav_items[:4] if nav_items else ["Overview", "Solutions", "Process", "Contact"]
    anchors = ["#overview", "#solutions", "#process", "#contact"]
    nav_html = "".join(
        f'<a href="{anchors[i % len(anchors)]}">{html.escape(label)}</a>'
        for i, label in enumerate(nav_links)
    )

    cards_html = "".join(
        f"""
        <article class="card">
          <div class="card-num">0{i}</div>
          <h3>{html.escape(title)}</h3>
          <p>{html.escape(body)}</p>
        </article>
        """
        for i, (title, body) in enumerate(feature_cards, 1)
    )

    steps_html = "".join(
        f"""
        <div class="step">
          <h4>{html.escape(st_title)}</h4>
          <p>{html.escape(st_body)}</p>
        </div>
        """
        for st_title, st_body in process_steps
    )

    is_light = palette["bg"].lower() == "#f8fafc"
    border_col = "rgba(15,23,42,0.1)" if is_light else "rgba(255,255,255,0.1)"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{safe_brand} — {safe_vertical}</title>
  <style>
    :root {{
      --bg: {palette["bg"]};
      --surface: {palette["surface"]};
      --accent: {palette["accent"]};
      --text: {palette["text"]};
      --muted: {palette["muted"]};
      --border: {border_col};
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.65;
    }}
    .wrap {{ max-width: 1140px; margin: 0 auto; padding: 0 1.5rem; }}
    header {{
      border-bottom: 1px solid var(--border);
      padding: 1.15rem 0;
      position: sticky;
      top: 0;
      background: var(--bg);
      z-index: 20;
    }}
    .nav-bar {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
    }}
    .brand {{ font-size: 1.3rem; font-weight: 800; color: var(--accent); letter-spacing: -0.02em; }}
    nav a {{
      color: var(--muted);
      text-decoration: none;
      margin-left: 1.35rem;
      font-size: 0.95rem;
      font-weight: 500;
    }}
    nav a:hover {{ color: var(--accent); }}
    .hero {{
      background: {palette["hero_grad"]};
      border-bottom: 1px solid var(--border);
      padding: 4.5rem 0 4rem;
    }}
    .badge {{
      display: inline-block;
      padding: 0.3rem 0.85rem;
      border-radius: 999px;
      border: 1px solid var(--accent);
      color: var(--accent);
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1.1rem;
    }}
    h1 {{ font-size: clamp(2.1rem, 4.2vw, 3.4rem); line-height: 1.12; margin-bottom: 1.1rem; max-width: 820px; }}
    .lead {{ max-width: 720px; color: var(--muted); font-size: 1.12rem; margin-bottom: 1.75rem; }}
    .cta-row {{ display: flex; flex-wrap: wrap; gap: 0.85rem; }}
    .btn-primary {{
      background: var(--accent);
      color: #ffffff;
      padding: 0.78rem 1.45rem;
      border-radius: 10px;
      text-decoration: none;
      font-weight: 700;
      font-size: 0.95rem;
    }}
    .btn-secondary {{
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.78rem 1.35rem;
      border-radius: 10px;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.95rem;
    }}
    section {{ padding: 3.75rem 0; }}
    .sec-title {{ font-size: 1.65rem; font-weight: 700; margin-bottom: 0.45rem; }}
    .sec-sub {{ color: var(--muted); margin-bottom: 2rem; font-size: 0.98rem; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.35rem;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.75rem;
    }}
    .card-num {{
      font-size: 0.75rem;
      font-weight: 800;
      color: var(--accent);
      margin-bottom: 0.6rem;
      letter-spacing: 0.08em;
    }}
    .card h3 {{ color: var(--text); margin-bottom: 0.55rem; font-size: 1.15rem; }}
    .card p {{ color: var(--muted); font-size: 0.95rem; }}
    .process-band {{
      background: var(--surface);
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
    }}
    .step {{
      padding: 1.25rem;
      border-left: 3px solid var(--accent);
      background: var(--bg);
      border-radius: 0 12px 12px 0;
    }}
    .step h4 {{ color: var(--accent); margin-bottom: 0.4rem; font-size: 1.02rem; }}
    .step p {{ color: var(--muted); font-size: 0.92rem; }}
    .contact-box {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 2.25rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1.5rem;
    }}
    footer {{
      border-top: 1px solid var(--border);
      padding: 2rem 0;
      text-align: center;
      color: var(--muted);
      font-size: 0.88rem;
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap nav-bar">
      <div class="brand">{safe_brand}</div>
      <nav>{nav_html}</nav>
    </div>
  </header>
  <main>
    <div class="hero" id="overview">
      <div class="wrap">
        <span class="badge">{safe_vertical}</span>
        <h1>{safe_headline}</h1>
        <p class="lead">{safe_subheadline}</p>
        <div class="cta-row">
          <a href="#solutions" class="btn-primary">{safe_cta}</a>
          <a href="mailto:{support_email}" class="btn-secondary">Contact {safe_brand}</a>
        </div>
      </div>
    </div>

    <section id="solutions">
      <div class="wrap">
        <h2 class="sec-title">Core Capabilities</h2>
        <p class="sec-sub">Structured services and solutions delivered by {safe_brand} ({safe_domain}).</p>
        <div class="grid">{cards_html}</div>
      </div>
    </section>

    <section class="process-band" id="process">
      <div class="wrap">
        <h2 class="sec-title">How We Work</h2>
        <p class="sec-sub">Clear, transparent steps from initial inquiry to active delivery.</p>
        <div class="grid">{steps_html}</div>
      </div>
    </section>

    <section id="contact">
      <div class="wrap">
        <div class="contact-box">
          <div>
            <h2 class="sec-title" style="margin-bottom:0.35rem;">Connect With {safe_brand}</h2>
            <p style="color:var(--muted);font-size:0.95rem;">Direct inquiries for {safe_domain} are handled by our dedicated desk.</p>
          </div>
          <a href="mailto:{support_email}" class="btn-primary">{support_email}</a>
        </div>
      </div>
    </section>
  </main>
  <footer>
    <div class="wrap">
      <p>&copy; {datetime.now().year} {safe_brand} ({safe_domain}). All rights reserved. • <a href="mailto:{support_email}" style="color:var(--accent);text-decoration:none;">{support_email}</a></p>
    </div>
  </footer>
</body>
</html>
"""


def _generate_ai_html(
    domain: str,
    brand_name: str,
    vertical_label: str,
    instruction_text: str,
    palette: dict,
    llm_api_key: str = "",
) -> Optional[str]:
    api_key = (llm_api_key or "").strip() or DEFAULT_LLM_KEY
    if not api_key or not instruction_text.strip():
        return None
    try:
        resp = SHARED_HTTP.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": os.environ.get("OPENAI_SITE_MODEL", "gpt-4o-mini"),
                "temperature": 0.7,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a senior frontend web designer. Return ONLY a complete, production-grade, "
                            "self-contained responsive HTML5 page starting with <!DOCTYPE html>. Include rich CSS styling, "
                            "sticky header navigation, hero section, 3-4 feature cards, process/highlights section, and footer. "
                            "Never include phone numbers. No markdown fences."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Brand: {brand_name}\nDomain: {domain}\nIndustry Vertical: {vertical_label}\n"
                            f"Primary Accent Color: {palette['accent']}\nContact Email: support@{domain}\n"
                            f"Design & Content Brief:\n{instruction_text.strip()}"
                        ),
                    },
                ],
            },
            timeout=30,
        )
        if resp.ok:
            content = resp.json()["choices"][0]["message"]["content"].strip()
            content = re.sub(r"^```html\s*|\s*```$", "", content, flags=re.I).strip()
            if content.lower().startswith("<!doctype html") or "<html" in content.lower():
                return content
    except Exception:
        pass
    return None


def _synthesize_prompt_blueprint(brand_name: str, domain: str, vertical_label: str, prompt_text: str, bp: dict) -> dict:
    clean_p = re.sub(r"\s+", " ", prompt_text).strip()
    sentences = [s.strip() for s in re.split(r"[.!?\n]+", clean_p) if len(s.strip()) >= 8]
    headline = sentences[0][:105] if sentences else f"{brand_name}: {clean_p[:95]}"
    if brand_name.lower() not in headline.lower():
        headline = f"{brand_name} — {headline}"
    subheadline = (
        " ".join(sentences[1:3])[:230]
        if len(sentences) > 1
        else f"{clean_p}. Tailored {vertical_label.lower()} experience built for {domain}."
    )

    chunks = [c.strip() for c in re.split(r"[,;|\n]+", clean_p) if len(c.strip()) >= 6]
    cards = []
    for i in range(3):
        if i < len(chunks):
            topic = chunks[i][:55].rstrip(".")
            cards.append((
                topic.title(),
                f"Dedicated {topic.lower()} workflow engineered for {brand_name} ({domain}) with responsive presentation and clear guidance.",
            ))
        else:
            cards.append(bp["cards"][i])

    return {
        "headline": headline,
        "subheadline": subheadline,
        "cta": bp["cta"],
        "nav": ["Overview", "Features", "Workflow", "Contact"],
        "cards": cards,
        "steps": bp["steps"],
    }


def build_s3_website_html(
    domain: str,
    site_vertical: str = "auto",
    site_prompt: str = "",
    reference_url: str = "",
    ref_summary: Optional[dict] = None,
    llm_api_key: str = "",
) -> Tuple[str, str]:
    clean_domain = domain.strip().lower()
    brand_name = _brand_from_domain(clean_domain)
    v_key = _resolve_vertical_key(clean_domain, site_vertical)
    bp = VERTICAL_BLUEPRINTS[v_key]
    vertical_label = bp["label"]
    palette = dict(_pick_palette(clean_domain))
    clean_prompt = (site_prompt or "").strip()
    clean_ref = (reference_url or "").strip()

    if clean_prompt:
        ai_html = _generate_ai_html(
            domain=clean_domain,
            brand_name=brand_name,
            vertical_label=vertical_label,
            instruction_text=clean_prompt,
            palette=palette,
            llm_api_key=llm_api_key,
        )
        if ai_html:
            return ai_html, "AI Prompt"

        syn = _synthesize_prompt_blueprint(brand_name, clean_domain, vertical_label, clean_prompt, bp)
        return _render_rich_responsive_html(
            domain=clean_domain,
            brand_name=brand_name,
            vertical_label=vertical_label,
            headline=syn["headline"],
            subheadline=syn["subheadline"],
            cta_label=syn["cta"],
            nav_items=syn["nav"],
            feature_cards=syn["cards"],
            process_steps=syn["steps"],
            palette=palette,
        ), "Prompt Builder"

    if clean_ref:
        ref_info = ref_summary or _fetch_reference_summary(clean_ref)
        if ref_info.get("accent_color"):
            palette["accent"] = ref_info["accent_color"]
        ref_label = ref_info.get("title") or ref_info.get("host") or clean_ref

        ai_html = _generate_ai_html(
            domain=clean_domain,
            brand_name=brand_name,
            vertical_label=vertical_label,
            instruction_text=(
                f"Create an original website for {brand_name} ({clean_domain}) inspired by the layout, "
                f"section rhythm, and visual hierarchy of {clean_ref}.\n"
                f"Reference Title: {ref_label}\n"
                f"Reference Description: {ref_info.get('description') or 'N/A'}\n"
                f"Reference Navigation: {', '.join(ref_info.get('nav_items') or []) or 'Overview, Solutions, Process, Contact'}\n"
                f"Reference Headings: {', '.join(ref_info.get('headings') or []) or 'N/A'}"
            ),
            palette=palette,
            llm_api_key=llm_api_key,
        )
        if ai_html:
            return ai_html, "AI Ref URL"

        ref_headings = ref_info.get("headings") or []
        ref_snippets = ref_info.get("snippets") or []
        raw_hero = ref_headings[0] if ref_headings else bp["tagline"]
        headline = raw_hero if brand_name.lower() in raw_hero.lower() else f"{brand_name}: {raw_hero}"
        subheadline = ref_info.get("description") or bp["lead"]

        cards = []
        for i in range(3):
            c_title = ref_headings[i + 1] if (i + 1) < len(ref_headings) else bp["cards"][i][0]
            c_body = ref_snippets[i] if i < len(ref_snippets) else bp["cards"][i][1]
            cards.append((c_title, c_body))

        return _render_rich_responsive_html(
            domain=clean_domain,
            brand_name=brand_name,
            vertical_label=vertical_label,
            headline=headline,
            subheadline=subheadline,
            cta_label=bp["cta"],
            nav_items=ref_info.get("nav_items") or ["Overview", "Solutions", "Process", "Contact"],
            feature_cards=cards,
            process_steps=bp["steps"],
            palette=palette,
        ), f"Ref ({ref_info.get('host') or 'URL'})"

    return _render_rich_responsive_html(
        domain=clean_domain,
        brand_name=brand_name,
        vertical_label=vertical_label,
        headline=f"{brand_name} — {bp['tagline']}",
        subheadline=bp["lead"],
        cta_label=bp["cta"],
        nav_items=["Overview", "Solutions", "Process", "Contact"],
        feature_cards=bp["cards"],
        process_steps=bp["steps"],
        palette=palette,
    ), vertical_label


# ==========================================
# TAB 8: AWS S3 DEPLOY / VERIFY / TEARDOWN (UNLIMITED)
# ==========================================
@app.post("/api/bulk-s3-deploy")
async def bulk_s3_deploy(
    request: Request,
    domains_text: str = Form(""),
    s3_operation: str = Form("deploy"),
    site_vertical: str = Form("auto"),
    reference_url: str = Form(""),
    site_prompt: str = Form(""),
    llm_api_key: str = Form(""),
    openai_key_id: str = Form(""),
    aws_access_key: str = Form(""),
    aws_secret_key: str = Form(""),
    aws_key_id: str = Form(""),
    aws_region: str = Form("us-east-1"),
    add_www_cname: str = Form(""),
    set_flexible_ssl: str = Form(""),
    always_https: str = Form(""),
    verify_after_deploy: str = Form(""),
    dry_run: str = Form(""),
    request_delay_ms: int = Form(0),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="s3", require_write=(s3_operation != "verify_only" and dry_run != "true"))
    cf_sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    aws_sec, _ = resolve_saved_key_secret(user, "s3", aws_key_id, {"ak": aws_access_key, "sk": aws_secret_key})
    llm_sec, _ = resolve_saved_key_secret(user, "openai", openai_key_id, {"key": llm_api_key})

    cf_token = (cf_sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    ak = (aws_sec.get("ak") or aws_access_key or "").strip() or DEFAULT_AWS_KEY
    sk = (aws_sec.get("sk") or aws_secret_key or "").strip() or DEFAULT_AWS_SECRET
    resolved_llm_key = (llm_sec.get("key") or llm_api_key or "").strip() or DEFAULT_LLM_KEY

    if not cf_token or not ak or not sk:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare Token or AWS Credentials'})}\n\n"
        return sse_response(err_stream())

    region = aws_region.strip() or "us-east-1"
    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    is_dry_run = dry_run == "true"
    delay_sec = max(0, min(int(request_delay_ms or 0), 5000)) / 1000.0
    ref_summary = _fetch_reference_summary(reference_url) if reference_url.strip() else None
    s3 = boto3.client("s3", region_name=region, aws_access_key_id=ak, aws_secret_access_key=sk)
    session = create_session(cf_token)
    cache = {}
    log_activity(user, "bulk_s3_run", "domains", str(len(domains)), f"op={s3_operation}, region={region}")

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
                s3_status = "S3 Deleted"
                try:
                    paginator = s3.get_paginator("list_object_versions")
                    for page in paginator.paginate(Bucket=dom):
                        to_delete = []
                        for v in page.get("Versions", []):
                            to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
                        for m in page.get("DeleteMarkers", []):
                            to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
                        if to_delete:
                            for i in range(0, len(to_delete), 1000):
                                s3.delete_objects(Bucket=dom, Delete={"Objects": to_delete[i:i + 1000]})

                    objs = s3.list_objects_v2(Bucket=dom).get("Contents", [])
                    if objs:
                        for i in range(0, len(objs), 1000):
                            s3.delete_objects(Bucket=dom, Delete={"Objects": [{"Key": o["Key"]} for o in objs[i:i + 1000]]})

                    s3.delete_bucket(Bucket=dom)
                except Exception as s3_err:
                    s3_status = f"S3 Err: {str(s3_err)[:70]}"

                cf_notes = []
                if zone_id:
                    for rec_name in ("@", "www"):
                        ok_c, msg_c = manage_dns_record(session, zone_id, root, "delete", "CNAME", rec_name)
                        if not ok_c:
                            cf_notes.append(msg_c)
                    if not cf_notes:
                        cf_notes.append("CF CNAMEs Cleared")
                else:
                    cf_notes.append("No CF Zone")

                all_ok = s3_status == "S3 Deleted" and (not zone_id or "CF CNAMEs Cleared" in cf_notes)
                return {
                    "index": idx, "total": total, "domain": dom, "account": acc,
                    "target": "Teardown", "result": f"{s3_status} | {', '.join(cf_notes)}",
                    "extra": "-", "ok": all_ok,
                }

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
            html_body, gen_mode_label = build_s3_website_html(
                domain=dom,
                site_vertical=site_vertical,
                site_prompt=site_prompt,
                reference_url=reference_url,
                ref_summary=ref_summary,
                llm_api_key=resolved_llm_key,
            )
            s3.put_object(Bucket=dom, Key="index.html", Body=html_body.encode("utf-8"), ContentType="text/html; charset=utf-8")

            s3_endpoint = f"{dom}.s3-website-{region}.amazonaws.com" if region != "us-east-1" else f"{dom}.s3-website-us-east-1.amazonaws.com"
            if zone_id:
                manage_dns_record(session, zone_id, root, "replace", "CNAME", "@", s3_endpoint, proxied=True)
                if add_www_cname == "true":
                    manage_dns_record(session, zone_id, root, "replace", "CNAME", "www", dom, proxied=True)
                if set_flexible_ssl == "true":
                    session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", json={"value": "flexible"}, timeout=TIMEOUT)
                if always_https == "true":
                    session.patch(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/always_use_https", json={"value": "on"}, timeout=TIMEOUT)

            extra = f"Deployed ({gen_mode_label})"
            if verify_after_deploy == "true":
                try:
                    vr = SHARED_HTTP.get(f"https://{dom}", timeout=6)
                    extra = f"HTTP {vr.status_code} ({gen_mode_label})"
                except Exception:
                    extra = f"Propagating ({gen_mode_label})"

            if delay_sec > 0:
                time.sleep(delay_sec)

            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": s3_endpoint, "result": "Deployed S3 & CF CNAME", "extra": extra, "ok": True}
        except Exception as exc:
            return {"index": idx, "total": total, "domain": dom, "account": acc, "target": "S3 Deploy", "result": str(exc) or type(exc).__name__, "extra": "-", "ok": False}

    return sse_response(run_parallel_stream(request, domains, work, concurrency=6))


# ==========================================
# TAB 9: GOOGLE POSTMASTER (UNLIMITED)
# ==========================================
@app.post("/api/bulk-postmaster")
async def bulk_postmaster(
    request: Request,
    domains_text: str = Form(""),
    pm_mode: str = Form("google_api_auto"),
    google_oauth_token: str = Form(""),
    google_key_id: str = Form(""),
    manual_txt_token: str = Form(""),
    propagation_wait: int = Form(1),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="pm", require_write=True)
    cf_sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    g_sec, _ = resolve_saved_key_secret(user, "google", google_key_id, {"token": google_oauth_token})
    cf_token = (cf_sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    g_token = (g_sec.get("token") or google_oauth_token or "").strip() or DEFAULT_GOOGLE_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    domains = [d.strip().lower() for d in domains_text.splitlines() if d.strip()]
    session = create_session(cf_token)
    cache = {}
    wait_sec = max(0, min(int(propagation_wait or 0), 10))
    log_activity(user, "bulk_postmaster_run", "domains", str(len(domains)), f"mode={pm_mode}")

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
# TAB 10: YAHOO SENDER HUB (UNLIMITED)
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
async def yahoo_fetch_unverified(request: Request, yahoo_cookie: str = Form(""), yahoo_key_id: str = Form("")):
    user, _ = check_tab_permission(request, required_tab="ysh")
    y_sec, _ = resolve_saved_key_secret(user, "yahoo", yahoo_key_id, {"cookie": yahoo_cookie})
    y_cookie, y_headers = parse_yahoo_cookie_and_csrf(y_sec.get("cookie") or yahoo_cookie)
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
            "pairs_text": "\n".join(unverified_pairs),
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
    yahoo_key_id: str = Form(""),
    yahoo_csrf: str = Form(""),
    propagation_wait: int = Form(1),
    api_token: str = Form(""),
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="ysh", require_write=True)
    cf_sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    y_sec, _ = resolve_saved_key_secret(user, "yahoo", yahoo_key_id, {"cookie": yahoo_cookie})
    cf_token = (cf_sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    if not cf_token:
        async def err_stream():
            yield f"data: {json.dumps({'error': 'Missing Cloudflare API Token'})}\n\n"
        return sse_response(err_stream())

    y_cookie, y_headers = parse_yahoo_cookie_and_csrf(y_sec.get("cookie") or yahoo_cookie, yahoo_csrf)
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
    for host, tok in raw_entries:
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

    log_activity(user, "bulk_yahoo_run", "domains", str(len(entries)), "Yahoo Sender Hub sync")

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
# TAB 11: AMAZON SES (UNLIMITED + BULK DELETE)
# ==========================================
def merge_spf_record(cf_session, zone_id: str, root_domain: str, rel_name: str, include_domain: str = "amazonses.com"):
    return smart_merge_spf_record(cf_session, zone_id, root_domain, rel_name, f"v=spf1 include:{include_domain} ~all", ttl=1)


def ensure_single_dmarc(cf_session, zone_id: str, root_domain: str, dmarc_rel: str, dmarc_val: str):
    clean_root = root_domain.strip().rstrip(".").lower()
    clean_rel = dmarc_rel.strip().rstrip(".").lower()
    fqdn = clean_rel if clean_rel.endswith(f".{clean_root}") else f"{clean_rel}.{clean_root}"
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"

    try:
        r = cf_session.get(url, params={"type": "TXT", "name": fqdn, "per_page": 100}, timeout=TIMEOUT).json()
        for rec in (r.get("result", []) if r.get("success") else []):
            raw_c = _normalize_txt_content(rec.get("content", ""))
            if rec.get("name", "").strip().rstrip(".").lower() == fqdn and raw_c.lower().startswith("v=dmarc1"):
                return True, "DMARC Exists"

        cr = cf_session.post(url, json={"type": "TXT", "name": fqdn, "content": format_cf_txt(dmarc_val), "ttl": 1, "proxied": False}, timeout=TIMEOUT).json()
        if cr.get("success"):
            return True, "DMARC Created"
        return False, (cr.get("errors") or [{}])[0].get("message", "DMARC create failed")
    except Exception as e:
        return False, str(e)[:60]


def cleanup_ses_dns_records(cf_session: requests.Session, zone_id: str, root_domain: str, host: str, mail_from_sub: str = "mail") -> str:
    clean_host = host.strip().rstrip(".").lower()
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    deleted_items = []

    try:
        r = cf_session.get(url, params={"per_page": 200}, timeout=TIMEOUT).json()
        recs = r.get("result", []) if r.get("success") else []
        dkim_suffix = f"._domainkey.{clean_host}"
        dmarc_fqdn = f"_dmarc.{clean_host}"
        mf_clean = (mail_from_sub or "mail").strip().strip(".").lower()
        mf_fqdn = f"{mf_clean}.{clean_host}" if mf_clean else ""

        for rec in recs:
            rec_id = rec.get("id")
            rec_type = (rec.get("type") or "").upper()
            rec_name = (rec.get("name") or "").strip().rstrip(".").lower()
            rec_content = _normalize_txt_content(rec.get("content", ""))

            if rec_type == "CNAME" and rec_name.endswith(dkim_suffix) and "amazonses.com" in rec_content.lower():
                dr = cf_session.delete(f"{url}/{rec_id}", timeout=TIMEOUT).json()
                if dr.get("success"):
                    deleted_items.append("DKIM CNAME")

            elif mf_fqdn and rec_name == mf_fqdn and "amazonses.com" in rec_content.lower():
                dr = cf_session.delete(f"{url}/{rec_id}", timeout=TIMEOUT).json()
                if dr.get("success"):
                    deleted_items.append(f"MAIL FROM {rec_type}")

            elif rec_type == "TXT" and rec_name == dmarc_fqdn and rec_content.lower().startswith("v=dmarc1"):
                dr = cf_session.delete(f"{url}/{rec_id}", timeout=TIMEOUT).json()
                if dr.get("success"):
                    deleted_items.append("DMARC")

            elif rec_type == "TXT" and rec_name == clean_host and rec_content.lower().startswith("v=spf1"):
                parts = rec_content.split()
                filtered = [p for p in parts if p.lower() != "include:amazonses.com"]
                if len(filtered) < len(parts):
                    qualifiers = ("-all", "~all", "?all", "+all", "all")
                    remaining_mechs = [p for p in filtered if p.lower() != "v=spf1" and p.lower() not in qualifiers]
                    if not remaining_mechs:
                        dr = cf_session.delete(f"{url}/{rec_id}", timeout=TIMEOUT).json()
                        if dr.get("success"):
                            deleted_items.append("SES SPF Removed")
                    else:
                        ur = cf_session.put(
                            f"{url}/{rec_id}",
                            json={
                                "type": "TXT",
                                "name": clean_host,
                                "content": format_cf_txt(" ".join(filtered)),
                                "ttl": rec.get("ttl", 1),
                                "proxied": False,
                            },
                            timeout=TIMEOUT,
                        ).json()
                        if ur.get("success"):
                            deleted_items.append("SPF Cleaned")
    except Exception as e:
        return f"CF Cleanup Err: {str(e)[:50]}"

    return f"CF Cleaned ({len(deleted_items)} changes)" if deleted_items else "No SES CF Records Found"


@app.post("/api/bulk-ses-verify")
async def bulk_ses_verify(
    request: Request,
    domains_text: str = Form(""),
    ses_mode: str = Form("enroll_and_verify"),
    delete_cf_ses_dns: str = Form(""),
    aws_access_key: str = Form(""),
    aws_secret_key: str = Form(""),
    aws_key_id: str = Form(""),
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
    cf_key_id: str = Form(""),
):
    user, _ = check_tab_permission(request, required_tab="ses", require_write=(ses_mode != "check_status"))
    cf_sec, _ = resolve_saved_key_secret(user, "cf", cf_key_id, {"token": api_token})
    aws_sec, _ = resolve_saved_key_secret(user, "ses", aws_key_id, {"ak": aws_access_key, "sk": aws_secret_key})
    cf_token = (cf_sec.get("token") or api_token or "").strip() or DEFAULT_TOKEN
    ak = (aws_sec.get("ak") or aws_access_key or "").strip() or DEFAULT_AWS_KEY
    sk = (aws_sec.get("sk") or aws_secret_key or "").strip() or DEFAULT_AWS_SECRET

    need_cf = (ses_mode == "enroll_and_verify") or (ses_mode == "delete_domains" and delete_cf_ses_dns == "true")
    if (need_cf and not cf_token) or not ak or not sk:
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

    ses = boto3.client("sesv2", region_name=region, aws_access_key_id=ak, aws_secret_access_key=sk)
    ses_v1 = boto3.client("ses", region_name=region, aws_access_key_id=ak, aws_secret_access_key=sk)
    acc_info = ses.get_account()
    prod_label = "Production" if acc_info.get("ProductionAccessEnabled") else "Sandbox"
    cf_session = create_session(cf_token) if cf_token else None
    cache = {}
    log_activity(user, "bulk_ses_run", "domains", str(len(domains)), f"mode={ses_mode}, region={region}")

    def work(idx: int, total: int, host: str) -> dict:
        root_domain, _ = extract_root_and_sub(host)
        try:
            if ses_mode == "delete_domains":
                ses_msg = "Deleted from AWS SES"
                ses_ok = True
                try:
                    ses.delete_email_identity(EmailIdentity=host)
                except ses.exceptions.NotFoundException:
                    ses_msg = "Not in SES (Already Removed)"
                except Exception as del_err:
                    ses_msg = f"SES Delete Err: {str(del_err)[:65]}"
                    ses_ok = False

                cf_note = "CF DNS Untouched"
                acc_label = f"AWS SES ({prod_label})"
                if delete_cf_ses_dns == "true" and cf_session:
                    zone_id, cf_acc = get_zone_cached(cf_session, root_domain, cache)
                    if zone_id:
                        acc_label = cf_acc
                        cf_note = cleanup_ses_dns_records(cf_session, zone_id, root_domain, host, mail_from_sub)
                    else:
                        cf_note = "CF Zone Not Found"

                return {
                    "index": idx, "total": total, "domain": host, "account": acc_label,
                    "target": f"SES Delete ({region})",
                    "result": f"{ses_msg} | {cf_note}",
                    "extra": "DNS Cleaned" if delete_cf_ses_dns == "true" else "SES Only",
                    "ok": ses_ok,
                }

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


# ==========================================
# TAB 12: JOB HISTORY ENDPOINTS
# ==========================================
@app.get("/api/jobs")
async def get_jobs(request: Request):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, created_at, tab_id, endpoint, label, total, ok, fail FROM jobs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return {"jobs": [dict(r) for r in rows]}


@app.get("/api/jobs/{job_id}")
async def get_job_detail(request: Request, job_id: int):
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
async def delete_job(request: Request, job_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}