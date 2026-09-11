from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
)
from fastapi.responses import RedirectResponse

from backend.database.db import find_case_by_source, get_case, list_cases, save_case
from backend.models.schemas import (
    CaseListResponse,
    EmailReportResponse,
    GmailScanRequest,
)
from backend.services.correlation import correlate_cases
from backend.services.email_sources import EMLSource, GmailAuthError, GmailProviderError
from backend.services.gmail import (
    GmailSettings,
    authorization_url,
    connection_store,
    exchange_code,
    fetch_profile,
    get_source,
    validate_oauth_state,
)
from backend.services.pipeline import analyze_normalized_email

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_DIR", "evidence"))
router = APIRouter(prefix="/api/v1", tags=["Email Security API"])


def _error(code: str, message: str, status_code: int = 400) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message, "details": {}}})


async def _read_email(file: UploadFile | None, raw_email: str | None) -> bytes:
    if file is None and not raw_email:
        raise _error("NO_EMAIL_PROVIDED", "Provide an .eml file or raw_email.")
    if file is not None:
        filename = file.filename or ""
        if ".." in filename or "\x00" in filename:
            raise _error("INVALID_FILE_TYPE", "Filename contains unsafe path characters.")
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise _error("FILE_TOO_LARGE", "File exceeds 25 MB.", 413)
        return content
    encoded = raw_email.encode("utf-8", errors="replace")
    if len(encoded) > MAX_UPLOAD_BYTES:
        raise _error("FILE_TOO_LARGE", "Raw email exceeds 25 MB.", 413)
    return encoded


def _summary(case: dict[str, Any]) -> dict[str, Any]:
    explanation = case.get("user_explanation", {})
    return {
        key: case.get(key)
        for key in (
            "case_id", "case_number", "status", "risk_score", "risk_level", "confidence",
            "subject", "sender", "recipient", "created_at", "source_type", "source_message_id",
        )
    } | {
        "verdict": explanation.get("verdict"),
        "headline": explanation.get("headline"),
        "demo": case.get("source_type") == "GMAIL_MOCK",
    }


def _persist_case(case: dict[str, Any], evidence: bytes) -> dict[str, Any]:
    evidence_dir = EVIDENCE_ROOT / case["case_id"]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / "original.eml"
    evidence_path.write_bytes(evidence)
    case["evidence_path"] = str(evidence_path)
    save_case(case)
    return case


def _provider_error(exc: Exception) -> HTTPException:
    if isinstance(exc, GmailAuthError):
        return _error("GMAIL_REAUTH_REQUIRED", "Your Gmail connection is no longer valid. Please reconnect your account.", 401)
    if isinstance(exc, ValueError):
        return _error("GMAIL_MESSAGE_MALFORMED", str(exc), 422)
    return _error("GMAIL_PROVIDER_UNAVAILABLE", str(exc), 503)


def _oauth_redirect(settings: GmailSettings, result: str, error_code: str | None = None) -> RedirectResponse:
    params = {"gmail": result}
    if error_code:
        params["gmail_error"] = error_code
    frontend_url = settings.frontend_url or "http://localhost:3000"
    return RedirectResponse(f"{frontend_url}/?{urlencode(params)}", status_code=303)


def _connection_metadata(connection: Any) -> dict[str, Any]:
    return {
        "provider": connection.provider,
        "status": connection.status,
        "account_id": connection.account_id,
        "account_email": connection.account_email,
        "email_address": connection.account_email,
        "display_name": connection.display_name,
        "connected_at": connection.connected_at,
        "last_sync_at": connection.last_sync_at,
    }


def _require_case(case_id: str) -> dict[str, Any]:
    case = get_case(case_id)
    if case is None:
        raise _error("CASE_NOT_FOUND", "Case not found.", 404)
    return case


def _safe_case(case: dict[str, Any]) -> dict[str, Any]:
    safe_case = copy.deepcopy(case)
    explanation = safe_case.get("user_explanation", {})
    valid_evidence = {
        item.get("ioc_id") for item in safe_case.get("iocs", {}).get("items", [])
    } | {
        item.get("signal_id") for item in safe_case.get("risk_assessment", {}).get("signals", [])
    }
    for reason in explanation.get("why", []):
        citations = [item for item in reason.get("evidence_ids", []) if item in valid_evidence]
        reason["evidence_ids"] = citations or [reason["signal_id"]] if reason.get("signal_id") in valid_evidence else []
    parsed = dict(safe_case.get("parsed", {}))
    parsed.pop("body_html", None)
    parsed["body_text"] = parsed.get("body_text", "")[:4000]
    normalized = dict(parsed.get("normalized_email", {}))
    if normalized:
        normalized["text"] = normalized.get("text", "")[:4000]
        normalized.pop("html", None)
        parsed["normalized_email"] = normalized
    safe_case["parsed"] = parsed
    safe_case.pop("evidence_path", None)
    return safe_case


@router.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "online", "service": "CodeFlux Email Security", "version": "2.0.0"}


@router.get("/dashboard")
def dashboard(limit: int = Query(50, ge=1, le=100)) -> dict[str, Any]:
    cases, total = list_cases(limit=limit)
    counts = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
    for case in cases:
        verdict = case.get("user_explanation", {}).get("verdict", "SUSPICIOUS")
        counts[verdict] = counts.get(verdict, 0) + 1
    return {"total": total, "counts": counts, "cases": [_summary(case) for case in cases]}


@router.post("/analyze", response_model=EmailReportResponse, status_code=201)
async def analyze_endpoint(file: UploadFile | None = File(default=None), raw_email: str | None = Form(default=None)) -> dict[str, Any]:  # noqa: B008
    content = await _read_email(file, raw_email)
    try:
        normalized = EMLSource().normalize(content)
        case = _persist_case(analyze_normalized_email(normalized), content)
    except Exception as exc:
        raise _error("PARSE_FAILED", "Email could not be analyzed.", 422) from exc
    return _summary(case)


@router.get("/cases", response_model=CaseListResponse)
def cases_endpoint(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    cases, total = list_cases(limit, offset)
    return {"cases": [_summary(case) for case in cases], "total": total, "limit": limit, "offset": offset}


@router.get("/cases/{case_id}")
def case_detail(case_id: str) -> dict[str, Any]:
    return {"case": _safe_case(_require_case(case_id))}


@router.get("/cases/{case_id}/status")
def case_status(case_id: str) -> dict[str, Any]:
    case = _require_case(case_id)
    return {"case_id": case_id, "status": case["status"], "progress_pct": 100}


@router.get("/cases/{case_id}/verdict")
def verdict(case_id: str) -> dict[str, Any]:
    case = _require_case(case_id)
    return {"case_id": case_id, **case["risk_assessment"]}


@router.get("/cases/{case_id}/evidence")
def evidence(case_id: str) -> dict[str, Any]:
    case = _require_case(case_id)
    evidence_path = Path(case.get("evidence_path", ""))
    if not evidence_path.is_file():
        return {"case_id": case_id, "original_evidence_hash": case["original_evidence_hash"], "integrity_status": "MISSING"}
    actual_hash = f"sha256:{hashlib.sha256(evidence_path.read_bytes()).hexdigest()}"
    return {
        "case_id": case_id,
        "original_evidence_hash": case["original_evidence_hash"],
        "content_size_bytes": evidence_path.stat().st_size,
        "integrity_status": "VALID" if actual_hash == case["original_evidence_hash"] else "INVALID",
    }


@router.get("/cases/{case_id}/timeline")
def timeline(case_id: str) -> dict[str, Any]:
    case = _require_case(case_id)
    hops = case.get("forensic_timeline", [])
    return {"case_id": case_id, "hops": hops, "hop_count": len(hops)}


@router.get("/cases/{case_id}/graph")
def graph(case_id: str) -> dict[str, Any]:
    return _require_case(case_id).get("graph", {"nodes": [], "edges": []})


@router.get("/cases/{case_id}/related")
def related_cases(case_id: str) -> dict[str, Any]:
    _require_case(case_id)
    cases, _ = list_cases(limit=100)
    result = correlate_cases(cases)
    related = [
        cluster for cluster in result["clusters"]
        if case_id in cluster["case_ids"]
    ]
    return {"case_id": case_id, "clusters": related, "relationships": [
        relation for relation in result["relationships"] if case_id in relation["case_ids"]
    ]}


@router.get("/correlation/clusters")
def correlation_clusters(limit: int = Query(100, ge=2, le=100)) -> dict[str, Any]:
    cases, _ = list_cases(limit=limit)
    return correlate_cases(cases)


@router.get("/history")
def history(limit: int = Query(10, ge=1, le=50)) -> list[dict[str, Any]]:
    cases, _ = list_cases(limit=limit)
    return [_summary(case) for case in cases]


@router.post("/gmail/connect")
def gmail_connect() -> dict[str, Any]:
    settings = GmailSettings.from_env()
    if not settings.enabled:
        raise _error("GMAIL_DISABLED", "Gmail integration is disabled in this environment.", 503)
    if settings.mode == "mock":
        connection = connection_store.connect_mock()
        return {
            "connected": True,
            "mode": "mock",
            "demo": True,
            **_connection_metadata(connection),
        }
    if settings.mode != "live":
        raise _error("GMAIL_MODE_INVALID", "GMAIL_MODE must be mock or live.", 503)
    if not settings.live_configured:
        raise _error("GMAIL_NOT_CONFIGURED", "Live Gmail requires server-side Google OAuth configuration.", 503)
    return {"connected": False, "mode": "live", "demo": False, "authorization_url": authorization_url(settings)}


@router.get("/gmail/oauth/callback")
def gmail_oauth_callback(code: str | None = None, state: str | None = None, error: str | None = None) -> RedirectResponse:
    settings = GmailSettings.from_env()
    if error:
        return _oauth_redirect(settings, "error", "GMAIL_OAUTH_DENIED")
    if not code or not state or not validate_oauth_state(state, settings):
        return _oauth_redirect(settings, "error", "GMAIL_OAUTH_STATE_INVALID")
    try:
        token_payload = exchange_code(code, settings)
        profile = fetch_profile(str(token_payload["access_token"]))
        connection_store.connect_live({
            **token_payload,
            **profile,
            "email": str(profile["emailAddress"]),
        })
    except GmailAuthError:
        return _oauth_redirect(settings, "error", "GMAIL_PERMISSION_DENIED")
    except GmailProviderError:
        return _oauth_redirect(settings, "error", "GMAIL_CONNECT_FAILED")
    return _oauth_redirect(settings, "connected")


@router.get("/gmail/status")
def gmail_status() -> dict[str, Any]:
    settings = GmailSettings.from_env()
    connection = connection_store.get()
    if not connection:
        return {
            "enabled": settings.enabled,
            "configured": settings.live_configured,
            "connected": False,
            "mode": settings.mode,
            "demo": settings.mode == "mock",
            "provider": "gmail",
            "status": "disconnected",
            "account_id": None,
            "account_email": None,
            "email_address": None,
            "display_name": None,
            "connected_at": None,
            "last_sync_at": None,
        }
    return {
        "enabled": settings.enabled,
        "configured": settings.live_configured if connection.mode == "live" else True,
        "connected": True,
        "mode": connection.mode,
        "demo": connection.mode == "mock",
        "scopes": ["gmail.readonly"] if connection.mode == "live" else ["synthetic.readonly"],
        **_connection_metadata(connection),
    }


@router.get("/gmail/messages")
def gmail_messages(limit: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    try:
        source = get_source()
        messages = source.list_messages(limit=limit)
        connection_store.mark_sync()
    except GmailProviderError as exc:
        raise _provider_error(exc) from exc
    return {"messages": messages, "count": len(messages), "limit": limit, "demo": GmailSettings.from_env().mode == "mock"}


@router.post("/gmail/messages/{message_id}/analyze", status_code=201)
def analyze_gmail_message(message_id: str, response: Response) -> dict[str, Any]:
    try:
        source = get_source()
        normalized = source.get_message(message_id)
        connection_store.mark_sync()
    except KeyError as exc:
        raise _error("GMAIL_MESSAGE_NOT_FOUND", "The Gmail message could not be found.", 404) from exc
    except (GmailProviderError, ValueError) as exc:
        raise _provider_error(exc) from exc
    existing = find_case_by_source(normalized.source_type, normalized.source_message_id, normalized.account_id)
    if existing:
        response.status_code = 200
        return {**_summary(existing), "reused": True}
    try:
        case = _persist_case(analyze_normalized_email(normalized), normalized.raw_bytes)
    except Exception as exc:
        raise _error("GMAIL_MESSAGE_ANALYSIS_FAILED", "The Gmail message could not be analyzed.", 422) from exc
    return {**_summary(case), "reused": False}


@router.post("/gmail/scan")
def scan_gmail(request: GmailScanRequest | None = None) -> dict[str, Any]:
    request = request or GmailScanRequest()
    try:
        source = get_source()
        messages = source.list_messages(limit=request.limit)
        connection_store.mark_sync()
    except GmailProviderError as exc:
        raise _provider_error(exc) from exc
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    analyzed_count = 0
    reused_count = 0
    for message in messages:
        message_id = str(message.get("message_id", ""))
        try:
            normalized = source.get_message(message_id)
            existing = find_case_by_source(normalized.source_type, normalized.source_message_id, normalized.account_id)
            if existing:
                reused_count += 1
                results.append({**_summary(existing), "reused": True})
                continue
            case = _persist_case(analyze_normalized_email(normalized), normalized.raw_bytes)
            analyzed_count += 1
            results.append({**_summary(case), "reused": False})
        except GmailAuthError as exc:
            raise _provider_error(exc) from exc
        except Exception as exc:  # noqa: BLE001
            errors.append({"message_id": message_id, "error": type(exc).__name__})
    return {
        "requested": request.limit,
        "returned": len(messages),
        "analyzed_count": analyzed_count,
        "reused_count": reused_count,
        "failed_count": len(errors),
        "errors": errors,
        "cases": results,
        "demo": GmailSettings.from_env().mode == "mock",
    }


@router.post("/gmail/disconnect")
def gmail_disconnect() -> dict[str, Any]:
    connection_store.disconnect()
    return {"connected": False, "disconnected": True, "provider": "gmail", "status": "disconnected"}
