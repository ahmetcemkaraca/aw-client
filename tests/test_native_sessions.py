import types
from unittest.mock import patch

import pytest

from aw_client.config import load_local_server_api_key


def test_native_token_cannot_be_sent_to_another_host_or_port(monkeypatch):
    monkeypatch.setenv("PEAKACTIVITY_API_TOKEN", "a" * 64)
    monkeypatch.setenv("PEAKACTIVITY_API_ORIGIN", "http://127.0.0.1:5610")
    assert load_local_server_api_key("localhost", 5610) == "a" * 64
    with pytest.raises(ValueError, match="different server"):
        load_local_server_api_key("example.invalid", 5610)
    with pytest.raises(ValueError, match="different server"):
        load_local_server_api_key("localhost", 5600)


def test_native_queue_does_not_create_plaintext_files(monkeypatch):
    from aw_client.client import RequestQueue
    monkeypatch.setenv("PEAKACTIVITY_CAPTURE", "1")
    with patch("aw_client.client.get_data_dir", side_effect=AssertionError("must not create persistent queue")):
        queue = RequestQueue(types.SimpleNamespace(client_name="test", testing=True))
        queue.add_request("buckets/test/heartbeat", {"data": {"app": "synthetic"}})
        assert queue._get_next().data["data"]["app"] == "synthetic"
        queue._task_done()


def test_expired_access_token_refreshes_once_before_retry(monkeypatch):
    from aw_client.client import ActivityWatchClient
    client = object.__new__(ActivityWatchClient)
    client.server_address = "http://127.0.0.1:5610"
    client.server_api_key = "a" * 64
    client.server_refresh_key = "b" * 64
    response = lambda status, body: types.SimpleNamespace(status_code=status, headers={}, json=lambda: body, raise_for_status=lambda: None)
    with patch("aw_client.client.req.get", side_effect=[response(401, {}), response(200, {})]) as get:
        with patch("aw_client.client.req.post", return_value=response(200, {"access_token": "c" * 64})) as post:
            client._get("info")
    assert get.call_count == 2
    assert post.call_args.kwargs["json"] == {"refresh_token": "b" * 64}
    assert client.server_api_key == "c" * 64
