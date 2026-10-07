"""Read-only auth adapter and detached metadata snapshots.

Only explicitly selected fields cross this boundary; never serialize auth objects.
"""

from datetime import datetime, timedelta
from typing import Any


def _metadata(value: Any) -> Any:
    """Convert known metadata values without repr-ing unknown objects."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return None


async def async_snapshot(auth: Any) -> dict[str, list[dict[str, Any]]]:
    """Enumerate users and their refresh tokens through the auth manager."""
    users = []
    tokens = []
    for user in await auth.async_get_users():
        users.append({
            "user_id": user.id,
            "name": _metadata(user.name),
            "is_active": _metadata(user.is_active),
            "is_owner": _metadata(user.is_owner),
            "system_generated": _metadata(user.system_generated),
        })
        for token in list(user.refresh_tokens.values()):
            tokens.append({
                "token_id": token.id,
                "user_id": user.id,
                "user_name": _metadata(user.name),
                **{
                    field: _metadata(getattr(token, field, None))
                    for field in (
                        "client_id", "client_name", "created_at",
                        "last_used_at", "last_used_ip", "token_type", "expire_at",
                    )
                },
                "access_token_expiration_seconds": _metadata(
                    getattr(token, "access_token_expiration", None)
                ),
            })
    return {"users": users, "tokens": tokens}
