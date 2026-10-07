"""Pure security observation model, retention, and allowlisted audit history."""

from datetime import datetime, timedelta, timezone
from collections.abc import Mapping
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit
import uuid

from .const import AUDIT_LIMIT


def utcnow():
    return datetime.now(timezone.utc)


def parse_time(value):
    try:
        result = datetime.fromisoformat(value)
        return result if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def safe_client(value):
    """Strip URL credentials/query/fragment; client identity is still untrusted."""
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme and parts.netloc:
            host = parts.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            if parts.port:
                host += f":{parts.port}"
            return urlunsplit((parts.scheme, host, parts.path, "", ""))[:512]
        return value.split("?", 1)[0].split("#", 1)[0][:512]
    except ValueError:
        return None


def safe_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def token_metadata(token):
    """Only metadata is persisted; token ID is a record ID, not a credential."""
    return {
        key: token.get(key) for key in (
            "token_id", "user_id", "created_at", "last_used_at", "token_type",
            "expire_at", "access_token_expiration_seconds",
        )
    } | {
        "client_id": safe_client(token.get("client_id")),
        "client_name": (token.get("client_name") or "")[:128] or None,
        "last_used_ip": safe_ip(token.get("last_used_ip")),
    }


class SecurityHistory:
    """Bounded local history and first-observed baselines across restarts."""

    def __init__(self, retention_days=30, data=None):
        self.retention_days = retention_days
        data = data or {}
        self.records = data.get("records", [])
        self.previous = data.get("previous")
        self.known_ips = data.get("known_ips", {})
        self.known_clients = data.get("known_clients", {})
        self.last_calls = data.get("last_calls", {})
        self.token_labels = data.get("token_labels", {})
        self.ip_context = data.get("ip_context", {})
        self.prune()

    def prune(self, now=None):
        cutoff = (now or utcnow()) - timedelta(days=self.retention_days)
        self.records = [
            row for row in self.records
            if (parse_time(row.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
        ][-AUDIT_LIMIT:]
        for collection in (self.known_ips, self.known_clients):
            for uid in list(collection):
                collection[uid] = {
                    value: stamp for value, stamp in collection[uid].items()
                    if (parse_time(stamp) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
                }
                if not collection[uid]:
                    del collection[uid]
        self.last_calls = {
            uid: row for uid, row in self.last_calls.items()
            if (parse_time(row.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
        }
        self.ip_context = {
            ip: row for ip, row in self.ip_context.items()
            if (parse_time(row.get("looked_up_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
        }

    def add(self, kind, user_id=None, now=None, **metadata):
        self.records.append({
            "id": uuid.uuid4().hex, "timestamp": (now or utcnow()).isoformat(),
            "kind": kind, "user_id": user_id, **metadata,
        })
        self.prune(now)

    def observe(self, snapshot, now=None):
        now = now or utcnow()
        self.prune(now)
        current = {row["token_id"]: token_metadata(row) for row in snapshot["tokens"]}
        baseline = self.previous is None
        old = self.previous or {}
        if baseline:
            self.add("baseline_initialized", now=now,
                     user_count=len(snapshot["users"]), token_count=len(current))
        for tid, row in current.items():
            uid = row["user_id"]
            if tid not in old:
                self.add("token_baseline" if baseline else "new_token", uid, now,
                         metadata=row)
            elif old[tid] != row:
                self.add("token_updated", uid, now, metadata=row)
            for key, collection, kind in (
                ("last_used_ip", self.known_ips, "new_ip"),
                ("client_id", self.known_clients, "new_client"),
            ):
                value = row.get(key)
                if value:
                    known = collection.setdefault(uid, {})
                    is_new = value not in known
                    known[value] = now.isoformat()
                    # Bound baseline memory even with hostile metadata.
                    while len(known) > 1000:
                        del known[next(iter(known))]
                    if is_new and not baseline:
                        self.add(kind, uid, now, value=value, token_id=tid)
        for tid in old.keys() - current.keys():
            self.add("token_removed", old[tid]["user_id"], now, token_id=tid)
        self.previous = current

    def service_call(self, data, context, now=None):
        """Record an invocation attributed by HA context, not its outcome."""
        uid = getattr(context, "user_id", None)
        if not uid:
            return False
        payload = data.get("service_data") or {}
        targets = payload.get("entity_id", []) if isinstance(payload, Mapping) else []
        if isinstance(targets, str):
            targets = targets.split(",")
        if not isinstance(targets, (list, tuple)):
            targets = []
        metadata = {
            "domain": str(data.get("domain", ""))[:64],
            "service": str(data.get("service", ""))[:64],
            "entity_ids": [
                v for v in targets[:50]
                if isinstance(v, str) and len(v) <= 255
                and re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", v)
            ],
            "context_id": getattr(context, "id", None),
            "parent_id": getattr(context, "parent_id", None),
            "outcome": "not_observed",
        }
        self.add("service_call", uid, now, **metadata)
        self.last_calls[uid] = self.records[-1]
        return True

    def query(self, text="", user_id=None, kind=None, since=None, until=None,
              limit=100, offset=0):
        self.prune()
        rows = [
            row for row in reversed(self.records)
            if (not user_id or row["user_id"] == user_id)
            and (not kind or row["kind"] == kind)
            and (not since or row["timestamp"] >= since)
            and (not until or row["timestamp"] <= until)
            and (not text or text.casefold() in json.dumps(row).casefold())
        ]
        return {"total": len(rows), "records": rows[offset:offset + limit]}

    def serialize(self):
        self.prune()
        return {
            "records": self.records, "previous": self.previous,
            "known_ips": self.known_ips, "known_clients": self.known_clients,
            "last_calls": self.last_calls,
            "token_labels": self.token_labels, "ip_context": self.ip_context,
        }

    def set_token_label(self, token_id, label):
        known = set(self.previous or {}) | set(self.token_labels) | {
            row.get("metadata", {}).get("token_id") for row in self.records
        }
        if token_id not in known:
            raise ValueError("Unknown token record ID")
        label = label.strip()
        if label:
            if token_id not in self.token_labels and len(self.token_labels) >= 1000:
                raise ValueError("Credential label limit reached")
            self.token_labels[token_id] = label[:128]
        else:
            self.token_labels.pop(token_id, None)

    def summary(self, user_id, tokens, recent_minutes=15, now=None):
        now = now or utcnow()
        candidates = []
        for token in tokens:
            stamp = parse_time(token.get("last_used_at"))
            if stamp and stamp <= now:
                candidates.append((stamp, token))
        latest = max(candidates, key=lambda item: item[0]) if candidates else None
        call = self.last_calls.get(user_id)
        activity = [latest[0]] if latest else []
        if call and (stamp := parse_time(call["timestamp"])) and stamp <= now:
            activity.append(stamp)
        last_observed = max(activity) if activity else None
        return {
            "last_token_use": latest[0] if latest else None,
            "last_service_call": parse_time(call["timestamp"]) if call else None,
            "recently_observed": bool(last_observed and now - last_observed <= timedelta(minutes=recent_minutes)),
            "latest_ip": safe_ip(latest[1].get("last_used_ip")) if latest else None,
            "latest_client": (
                safe_client(latest[1].get("client_id"))
                or (latest[1].get("client_name") or "")[:128] or None
            ) if latest else None,
            "known_ip_count": len(self.known_ips.get(user_id, {})),
            "new_observation_count": sum(
                row["user_id"] == user_id and row["kind"] in ("new_ip", "new_client", "new_token")
                for row in self.records
            ),
        }

    def token_activity(self, user_id, tokens, recent_minutes=15, now=None):
        """Expose bounded credential activity, never claim live connections."""
        now = now or utcnow()
        rows = []
        for token in tokens:
            row = token_metadata(token)
            stamp = parse_time(row.get("last_used_at"))
            expiry = row.get("expire_at")
            expired = isinstance(expiry, (int, float)) and expiry <= now.timestamp()
            row["recently_used"] = bool(
                stamp and timedelta(0) <= now - stamp <= timedelta(minutes=recent_minutes)
                and not expired
            )
            row["expired"] = expired
            rows.append(row)
        rows.sort(key=lambda row: row.get("last_used_at") or "", reverse=True)
        observations = []
        for record in reversed(self.records):
            metadata = record.get("metadata")
            if record.get("user_id") != user_id or not isinstance(metadata, dict):
                continue
            if not metadata.get("last_used_ip"):
                continue
            observation = token_metadata(metadata)
            observation["observed_at"] = record["timestamp"]
            observation["observation_kind"] = record["kind"]
            observations.append(observation)
        from .network import ip_scope
        current_ids = {row["token_id"] for row in rows}
        removed = {}
        for record in reversed(self.records):
            observation = record.get("metadata")
            if record.get("user_id") != user_id or not isinstance(observation, dict):
                continue
            tid = observation["token_id"]
            if tid not in current_ids and tid not in removed:
                removed[tid] = {**observation, "recently_used": False, "expired": False}
        for row in rows + list(removed.values()):
            tid = row["token_id"]
            row["label"] = self.token_labels.get(tid) or row.get("client_name") or row.get("client_id") or "Unknown client"
            row["credential_status"] = "removed" if tid in removed else "expired" if row["expired"] else "present"
            row["activity"] = "removed" if tid in removed else "expired" if row["expired"] else "recently_used" if row["recently_used"] else "outside_window" if row.get("last_used_at") else "never_observed"
            row["ip_scope"] = ip_scope(row.get("last_used_ip"))
            row["ip_context"] = self.ip_context.get(row.get("last_used_ip"), {})
            relevant = [item for item in observations if item["token_id"] == tid]
            row["ip_changed"] = len({item["last_used_ip"] for item in relevant}) > 1
            row["new_credential"] = any(record["kind"] == "new_token" and record.get("metadata", {}).get("token_id") == tid for record in self.records)
            evidence = [record for record in self.records if record.get("user_id") == user_id
                        and (record.get("metadata", {}).get("token_id") == tid or record.get("token_id") == tid)]
            row["first_observed_at"] = evidence[0]["timestamp"] if evidence else None
            row["removed_at"] = next((record["timestamp"] for record in reversed(evidence)
                                      if record["kind"] == "token_removed"), None)
            row["new_ip"] = any(record["kind"] == "new_ip" and record.get("token_id") == tid
                                and record.get("value") == row.get("last_used_ip") for record in self.records)
        for observation in observations:
            observation["label"] = self.token_labels.get(observation["token_id"]) or observation.get("client_name") or observation.get("client_id") or "Unknown client"
            observation["ip_context"] = self.ip_context.get(observation["last_used_ip"], {})
        connections = rows + list(removed.values())
        return {
            "recently_used_token_count": sum(row["recently_used"] for row in rows),
            "tokens": rows[:100],
            "tokens_total": len(rows),
            "tokens_truncated": len(rows) > 100,
            "ip_observations": observations[:100],
            "ip_observations_total": len(observations),
            "ip_observations_truncated": len(observations) > 100,
            "retention_days": self.retention_days,
            "connections": connections[:100],
            "connections_total": len(connections),
            "connections_truncated": len(connections) > 100,
        }
