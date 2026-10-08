"""Explainable conservative login assessment from bounded, local observations."""
from datetime import timedelta
from .security import safe_ip, safe_client, parse_time, utcnow
from .network import ip_scope

RANK = {"normal": 0, "review": 1, "likely_issue": 2}


def login_rows(history, now=None):
    now = now or utcnow()
    return [row for row in history.records if row["kind"] in ("login_success", "login_failure")
            and now - timedelta(hours=24) <= (parse_time(row["timestamp"]) or now - timedelta(days=2)) <= now]


def record_login(history, outcome, source_ip=None, user_id=None, token_id=None,
                 client_id=None, failure_reason=None, now=None, user_name=None):
    now = now or utcnow()
    ip = safe_ip(source_ip)
    if outcome == "failure":
        history.add("login_failure", now=now, source_ip=ip,
                    failure_reason=failure_reason if failure_reason in ("invalid_auth", "invalid_code") else "invalid_auth",
                    attribution="unknown_user")
        return
    if outcome != "success" or not user_id:
        return
    # A previous success ends the failure sequence on this IP; shared NAT is not identity.
    successes = [parse_time(r["timestamp"]) for r in login_rows(history, now)
                 if r["kind"] == "login_success" and r.get("source_ip") == ip and ip]
    cutoff = max([now - timedelta(minutes=10)] + [t for t in successes if t])
    failures = [r for r in login_rows(history, now) if r["kind"] == "login_failure" and ip
                and r.get("source_ip") == ip and cutoff < parse_time(r["timestamp"]) <= now]
    recognized = history.recognized.get(user_id, {})
    unfamiliar = bool(ip and ip_scope(ip) == "public" and
                      ip not in history.known_ips.get(user_id, {}) and ip not in recognized.get("ips", {}))
    new_credential = bool(token_id and token_id not in (history.previous or {}) and
                          token_id not in recognized.get("tokens", {}))
    reasons = []
    level = "normal"
    if len(failures) >= 5:
        level = "review"
        reasons.append(f"Successful login after {len(failures)} failed attempts from the same IP within 10 minutes; IP correlation does not identify the failed user")
    if unfamiliar and new_credential:
        level = "review"
        reasons.append("New credential and unfamiliar public IP")
    if len(failures) >= 10 and unfamiliar and new_credential:
        level = "likely_issue"
        reasons.append("Repeated failures followed by success with both an unfamiliar public IP and a new credential")
    history.add("login_success", user_id, now, user_name=user_name, token_id=token_id, client_id=safe_client(client_id),
                source_ip=ip, security_level=level, security_reasons=reasons,
                correlated_failure_count=len(failures), correlated_failure_ids=[r["id"] for r in failures[-100:]],
                correlated_failure_ids_truncated=len(failures) > 100,
                unfamiliar_public_ip=unfamiliar, new_credential=new_credential,
                meaning="Successful authorization-code exchange; passwordless providers may also use this flow")


def summary(history, user_id=None, status="observing", now=None, network=False, include_events=True):
    rows = login_rows(history, now)
    successes = [r for r in rows if r["kind"] == "login_success" and (user_id is None or r["user_id"] == user_id)]
    failures = [r for r in rows if r["kind"] == "login_failure"]
    relevant = rows if user_id is None else successes
    events = []
    for row in reversed(relevant[-100:] if include_events else []):
        detail = history.with_user_names(row)
        if network:
            detail["ip_context"] = history.ip_context.get(row.get("source_ip"), {})
        else:
            for key in ("source_ip", "client_id", "token_id", "correlated_failure_ids"):
                detail.pop(key, None)
        events.append(detail)
    # Recognition suppresses novelty-only flags, never repeated-failure evidence.
    def assessed(row):
        if row.get("security_level") == "review" and row.get("correlated_failure_count", 0) < 5:
            recognized = history.recognized.get(row["user_id"], {})
            if row.get("token_id") in recognized.get("tokens", {}) or row.get("source_ip") in recognized.get("ips", {}):
                return "normal"
        return row.get("security_level", "normal")
    flagged = [r for r in successes if assessed(r) != "normal"]
    level = max((assessed(r) for r in flagged), key=RANK.get, default="normal") if status == "observing" else "unknown"
    reasons = list(dict.fromkeys(reason for r in flagged for reason in r.get("security_reasons", [])))
    if user_id is None and status == "observing":
        now = now or utcnow()
        pending = {}
        for row in rows:
            ip = row.get("source_ip")
            if not ip:
                continue
            if row["kind"] == "login_success":
                pending[ip] = 0
            elif parse_time(row["timestamp"]) >= now - timedelta(minutes=10):
                pending[ip] = pending.get(ip, 0) + 1
        bursts = [count for count in pending.values() if count >= 5]
        if bursts:
            if level == "normal":
                level = "review"
            reasons.append(f"Unattributed failure burst: up to {max(bursts)} attempts from one IP within 10 minutes")
    correlated = sum(r.get("correlated_failure_count", 0) for r in successes)
    return {"security_status": level, "security_reasons": reasons,
            "successful_logins_24h": len(successes), "failed_login_attempts_24h": len(failures) if user_id is None else None,
            "correlated_failed_attempts_24h": correlated,
            "last_successful_login": max((r["timestamp"] for r in successes), default=None),
            "login_events": events[:100], "login_events_truncated": len(relevant) > 100,
            "login_tracking_status": status,
            "meaning": "Observed authorization-code successes and explicit password/MFA failures; same-IP failures are correlation, not confirmed user attribution. Normal means no detected concern within coverage.",
            "window_hours": 24, "correlation_window_minutes": 10,
            "counts_scope": "Retained observed events, limited by monitoring coverage and the shared audit cap"}


def session_assessment(history, row):
    # Match both record ID and connection IP; credential's other IP is not this session.
    matches = [r for r in history.records if r["kind"] == "login_success"
               and r["user_id"] == row["user_id"] and r.get("token_id") == row.get("token_id")
               and r.get("source_ip") and r.get("source_ip") == row.get("source_ip")
               and parse_time(r["timestamp"]) and parse_time(row.get("first_observed_at"))
               and timedelta(0) <= parse_time(row["first_observed_at"]) - parse_time(r["timestamp"]) <= timedelta(minutes=10)]
    if not matches:
        return {"security_level": "unknown", "security_reasons": ["No matching observed login; a connection is not a password login"]}
    event = matches[-1]
    return {"security_level": event["security_level"], "security_reasons": event["security_reasons"], "login_event_id": event["id"]}
