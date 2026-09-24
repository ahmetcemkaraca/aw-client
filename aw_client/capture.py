"""Apply the native capture policy before data enters a collector queue."""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import requests


def timestamp(value):
    if not isinstance(value, (datetime, str)):
        raise ValueError("Invalid capture timestamp")
    # Chrono emits nanoseconds; Python 3.8/3.9 ISO parsing accepts microseconds.
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00")) if isinstance(value, str) else None
    result = value if isinstance(value, datetime) else datetime.fromisoformat(text)
    if result.tzinfo is None:
        raise ValueError("Capture timestamps must include a timezone")
    return result


def load_policy():
    if os.environ.get("PEAKACTIVITY_CAPTURE") != "1":
        return None
    policy = json.loads(os.environ.get("PEAKACTIVITY_CAPTURE_POLICY", "null"))
    if not isinstance(policy, dict):
        raise ValueError("Native capture requires an explicit policy")
    for field in ("recording", "window", "idle", "browser", "titles", "urls", "paths"):
        if type(policy.get(field)) is not bool:
            raise ValueError("Invalid native capture permission")
    for field in ("excluded_apps", "excluded_domains"):
        if not isinstance(policy.get(field), list) or not all(isinstance(item, str) for item in policy[field]):
            raise ValueError("Invalid native capture exclusions")
    timestamp(policy["effective_from"])
    if policy.get("paused_until"):
        timestamp(policy["paused_until"])
    return policy


def clip_interval(policy, event_time, duration):
    if policy is None:
        return event_time, duration
    until = timestamp(policy["paused_until"]) if policy.get("paused_until") else None
    boundary = max(timestamp(policy["effective_from"]), until) if until else timestamp(policy["effective_from"])
    now = datetime.now(timezone.utc)
    end = event_time + duration
    if not policy["recording"] or now < boundary or duration < timedelta(0) or end > now + timedelta(seconds=5):
        return None
    if event_time < boundary:
        if end <= boundary:
            return None
        return boundary, end - boundary
    return event_time, duration


def filter_data(policy, bucket, data, event_time, duration=timedelta(0)):
    if policy is None:
        return dict(data)
    if clip_interval(policy, event_time, duration) is None:
        return None
    private = data.get("incognito", data.get("private"))
    if private is not None and private is not False:
        return None
    if bucket.startswith("aw-watcher-afk_"):
        status = data.get("status")
        return {"status": status} if policy["idle"] and isinstance(status, str) and status in {"afk", "not-afk"} else None
    if not bucket.startswith(("aw-watcher-window_", "aw-watcher-web_")):
        return None
    app = str(data.get("app", "")).lower()
    if any(excluded in app for excluded in policy["excluded_apps"]):
        return None
    browser = (bucket.startswith("aw-watcher-web_") or "url" in data
               or any(name in app for name in ("chrome", "chromium", "firefox", "safari", "brave", "msedge", "microsoft edge", "opera")))
    if browser:
        if not policy["browser"] or private is not False:
            return None
    elif bucket.startswith("aw-watcher-window_"):
        if not policy["window"]:
            return None
    elif bucket.startswith("aw-watcher-afk_"):
        if not policy["idle"]:
            return None
    else:
        return None
    data = dict(data)
    if "url" in data:
        try:
            # Public Requests URL preparation uses UTS-46 IDNA without making a request.
            # Python's built-in IDNA codec would incorrectly map some domains (e.g. ß).
            url = urlsplit(requests.Request("GET", data["url"]).prepare().url)
            if url.scheme not in {"http", "https"} or not url.hostname:
                return None
            host = url.hostname.rstrip(".").lower()
            if any(host == domain or host.endswith("." + domain) for domain in policy["excluded_domains"]):
                return None
            authority = "[" + host + "]" if ":" in host else host
            port = url.port
            if port is not None and port != (443 if url.scheme == "https" else 80):
                authority += ":" + str(port)
            data["url"] = url.scheme + "://" + authority
        except (TypeError, ValueError, UnicodeError, requests.RequestException):
            return None
    allowed = {"app"}
    allowed.update(field for field, enabled in (("title", policy["titles"]), ("url", policy["urls"]), ("path", policy["paths"])) if enabled)
    return {field: value for field, value in data.items()
            if (field in allowed and isinstance(value, str)) or (field in {"incognito", "private"} and value is False)}
