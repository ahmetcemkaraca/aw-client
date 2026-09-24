from datetime import datetime, timedelta, timezone
from aw_client.capture import filter_data, clip_interval, timestamp


def policy(**changes):
    value = dict(recording=True, paused_until=None, window=True, idle=True, browser=False,
                 titles=False, urls=False, paths=False, excluded_apps=["bitwarden"], excluded_domains=[],
                 effective_from=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
    value.update(changes)
    return value


def test_minimizes_before_queue_and_rejects_private_unknown_browser():
    now = datetime.now(timezone.utc)
    assert filter_data(policy(), "aw-watcher-window_test", {"app": "Editor", "title": "secret", "path": "/private", "clipboard": "secret"}, now) == {"app": "Editor"}
    assert filter_data(policy(browser=True), "aw-watcher-window_test", {"app": "Firefox"}, now) is None
    assert filter_data(policy(), "aw-watcher-window_test", {"app": "Bitwarden"}, now) is None


def test_url_origin_and_exclusion_match_storage_contract():
    now = datetime.now(timezone.utc)
    data = {"app": "Chrome", "incognito": False, "url": "https://user:password@example.org/path?secret#fragment"}
    result = filter_data(policy(browser=True, urls=True), "aw-watcher-window_test", data, now)
    assert result == {"app": "Chrome", "incognito": False, "url": "https://example.org"}
    data["url"] = "https://sub.example.org./secret"
    assert filter_data(policy(browser=True, urls=True, excluded_domains=["example.org"]), "aw-watcher-window_test", data, now) is None


def test_paused_and_pre_consent_events_never_enter_queue():
    now = datetime.now(timezone.utc)
    data = {"app": "Editor"}
    assert filter_data(policy(recording=False), "aw-watcher-window_test", data, now) is None
    assert filter_data(policy(paused_until=(now + timedelta(minutes=10)).isoformat()), "aw-watcher-window_test", data, now) is None
    assert filter_data(policy(), "aw-watcher-window_test", data, now - timedelta(days=1)) is None


def test_long_idle_interval_is_clipped_to_the_allowed_resume_time():
    now = datetime.now(timezone.utc)
    boundary = now - timedelta(seconds=5)
    consent = policy(effective_from=boundary.isoformat())
    assert clip_interval(consent, now - timedelta(seconds=20), timedelta(seconds=20)) == (boundary, timedelta(seconds=5))
    assert filter_data(consent, "aw-watcher-afk_test", {"status": "afk"}, now - timedelta(seconds=20), timedelta(seconds=20)) == {"status": "afk"}


def test_server_nanosecond_timestamp_is_supported_by_python_39():
    parsed = timestamp("2026-09-22T11:22:33.123456789Z")
    assert parsed == datetime(2026, 9, 22, 11, 22, 33, 123456, tzinfo=timezone.utc)


def test_url_fields_cannot_bypass_a_disabled_or_unknown_source():
    now = datetime.now(timezone.utc)
    data = {"status": "afk", "app": "Chrome", "incognito": False, "url": "https://example.org"}
    assert filter_data(policy(idle=False, browser=True), "aw-watcher-afk_test", data, now) is None
    assert filter_data(policy(browser=True), "unknown_test", data, now) is None
    assert filter_data(policy(browser=True), "aw-watcher-afk_test", data, now) == {"status": "afk"}


def test_idn_domain_exclusion_preserves_domain_identity():
    now = datetime.now(timezone.utc)
    data = {"app": "Chrome", "incognito": False, "url": "https://straße.de/private"}
    assert filter_data(policy(browser=True, urls=True, excluded_domains=["xn--strae-oqa.de"]), "aw-watcher-window_test", data, now) is None
    result = filter_data(policy(browser=True, urls=True), "aw-watcher-window_test", data, now)
    assert result["url"] == "https://xn--strae-oqa.de"


def test_native_heartbeat_does_not_leave_a_premerge_interval_on_pause():
    from types import SimpleNamespace
    from unittest.mock import Mock
    from aw_client.client import ActivityWatchClient
    from aw_core.models import Event
    client = object.__new__(ActivityWatchClient)
    client.capture_policy = policy()
    client.capture_continuous = set()
    client.last_heartbeat = {}
    client.commit_interval = 10
    client.request_queue = SimpleNamespace(add_request=Mock())
    client._post = Mock()
    client.heartbeat("aw-watcher-window_test", Event(timestamp=datetime.now(timezone.utc), data={"app": "Editor", "title": "secret"}), 2, queued=True)
    assert client._post.call_count == 1
    assert client._post.call_args.args[1]["data"] == {"app": "Editor", "capture_break": True}
    client.request_queue.add_request.assert_not_called()
    assert client.last_heartbeat == {}
