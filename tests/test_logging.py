from __future__ import annotations

import base64
import io
import logging
import os
from typing import Any

import pytest

from uvicorn.logging import AccessFormatter, GunicornAccessFormatter

pytestmark = pytest.mark.anyio


def test_basic_access_formatter() -> None:
    """Test basic access log formatting."""
    formatter = AccessFormatter(fmt='%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s')
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)

    logger = logging.getLogger("test_access")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info(
        '%s - "%s %s HTTP/%s" %d',
        "192.168.1.1:12345",
        "GET",
        "/test",
        "1.1",
        200,
    )
    output = stream.getvalue()

    assert "192.168.1.1:12345" in output
    assert "GET /test HTTP/1.1" in output
    assert "200" in output


def format_log(
    fmt: str, scope: dict[str, Any], status: int, response_time: float | None, response_size: int | None
) -> str:
    """Helper to format a log entry using GunicornAccessFormatter."""
    formatter = GunicornAccessFormatter(fmt=fmt, use_colors=False)

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="",
        args=(scope, status, response_time, response_size),
        exc_info=None,
    )

    return formatter.format(record)


def create_scope(
    method: str = "GET",
    path: str = "/test",
    query_string: bytes = b"foo=bar",
    client: tuple[str, int] | None = ("192.168.1.100", 12345),
    headers: list[tuple[bytes, bytes]] | None = None,
) -> dict[str, Any]:
    """Create a test ASGI scope."""
    if headers is None:
        headers = [
            (b"host", b"localhost:8000"),
            (b"user-agent", b"TestClient/1.0"),
            (b"referer", b"http://example.com/"),
        ]

    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "query_string": query_string,
        "root_path": "",
        "headers": headers,
        "server": ("localhost", 8000),
        "client": client,
    }


def test_remote_address_atom() -> None:
    scope = create_scope(client=("10.0.0.5", 54321))
    output = format_log("%(h)s", scope, 200, 0.123, 1024)
    assert output == "10.0.0.5"


def test_remote_logname_atom() -> None:
    scope = create_scope()
    output = format_log("%(l)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_username_atom_without_auth() -> None:
    scope = create_scope()
    output = format_log("%(u)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_username_atom_with_basic_auth() -> None:
    credentials = "admin:password"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = [(b"authorization", f"Basic {encoded}".encode())]
    scope = create_scope(headers=headers)
    output = format_log("%(u)s", scope, 200, 0.123, 1024)
    assert output == "admin"


def test_username_atom_with_special_chars() -> None:
    credentials = "user@example.com:password123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = [(b"authorization", f"Basic {encoded}".encode())]
    scope = create_scope(headers=headers)
    output = format_log("%(u)s", scope, 200, 0.123, 1024)
    assert output == "user@example.com"


def test_username_atom_with_invalid_auth() -> None:
    headers = [(b"authorization", b"Basic invalid!!!")]
    scope = create_scope(headers=headers)
    output = format_log("%(u)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_username_atom_with_bearer_token() -> None:
    headers = [(b"authorization", b"Bearer eyJhbGci...")]
    scope = create_scope(headers=headers)
    output = format_log("%(u)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_timestamp_atom() -> None:
    scope = create_scope()
    output = format_log("%(t)s", scope, 200, 0.123, 1024)
    # Should be in format [DD/Mon/YYYY:HH:MM:SS +ZZZZ]
    assert output.startswith("[")
    assert output.endswith("]")
    assert "/" in output
    assert ":" in output


def test_request_line_atom() -> None:
    scope = create_scope(method="POST", path="/api/users", query_string=b"page=1")
    output = format_log("%(r)s", scope, 200, 0.123, 1024)
    # May contain ANSI codes with colors, so just check main parts
    assert "POST" in output
    assert "/api/users?page=1" in output
    assert "HTTP/1.1" in output


def test_method_atom() -> None:
    scope = create_scope(method="DELETE")
    output = format_log("%(m)s", scope, 204, 0.123, 0)
    assert output == "DELETE"


def test_url_path_atom() -> None:
    scope = create_scope(path="/api/users/123", query_string=b"foo=bar")
    output = format_log("%(U)s", scope, 200, 0.123, 1024)
    assert output == "/api/users/123"


def test_query_string_atom() -> None:
    scope = create_scope(query_string=b"page=1&limit=10")
    output = format_log("%(q)s", scope, 200, 0.123, 1024)
    assert output == "page=1&limit=10"


def test_query_string_atom_empty() -> None:
    scope = create_scope(query_string=b"")
    output = format_log("%(q)s", scope, 200, 0.123, 1024)
    assert output == ""


def test_protocol_atom() -> None:
    scope = create_scope()
    scope["http_version"] = "2.0"
    output = format_log("%(H)s", scope, 200, 0.123, 1024)
    assert output == "2.0"


def test_status_atom() -> None:
    scope = create_scope()
    output = format_log("%(s)s", scope, 404, 0.123, 1024)
    assert output == "404"


def test_response_length_bytes_atom() -> None:
    scope = create_scope()
    output = format_log("%(B)s", scope, 200, 0.123, 2048)
    assert output == "2048"


def test_response_length_bytes_atom_zero() -> None:
    scope = create_scope()
    output = format_log("%(B)s", scope, 204, 0.123, 0)
    assert output == "0"


def test_response_length_clf_atom() -> None:
    scope = create_scope()
    output = format_log("%(b)s", scope, 200, 0.123, 1024)
    assert output == "1024"


def test_response_length_clf_atom_zero() -> None:
    scope = create_scope()
    output = format_log("%(b)s", scope, 204, 0.123, 0)
    assert output == "-"


def test_response_length_clf_atom_none() -> None:
    scope = create_scope()
    output = format_log("%(b)s", scope, 204, 0.123, None)
    assert output == "-"


def test_referer_atom() -> None:
    headers = [(b"referer", b"https://example.com/page")]
    scope = create_scope(headers=headers)
    output = format_log("%(f)s", scope, 200, 0.123, 1024)
    assert output == "https://example.com/page"


def test_referer_atom_missing() -> None:
    scope = create_scope(headers=[])
    output = format_log("%(f)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_user_agent_atom() -> None:
    headers = [(b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64)")]
    scope = create_scope(headers=headers)
    output = format_log("%(a)s", scope, 200, 0.123, 1024)
    assert output == "Mozilla/5.0 (X11; Linux x86_64)"


def test_user_agent_atom_missing() -> None:
    scope = create_scope(headers=[])
    output = format_log("%(a)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_response_time_seconds_atom() -> None:
    scope = create_scope()
    output = format_log("%(T)s", scope, 200, 1.234567, 1024)
    assert output == "1"


def test_response_time_microseconds_atom() -> None:
    scope = create_scope()
    output = format_log("%(D)s", scope, 200, 0.123456, 1024)
    # 0.123456 seconds = 123456 microseconds
    assert output == "123456"


def test_response_time_milliseconds_atom() -> None:
    scope = create_scope()
    output = format_log("%(M)s", scope, 200, 1.234567, 1024)
    # 1.234567 seconds = 1234 milliseconds
    assert output == "1234"


def test_response_time_decimal_atom() -> None:
    scope = create_scope()
    output = format_log("%(L)s", scope, 200, 1.234567, 1024)
    assert output == "1.234567"


def test_process_id_atom() -> None:
    scope = create_scope()
    output = format_log("%(p)s", scope, 200, 0.123, 1024)
    assert output == str(os.getpid())


def test_request_header_atom() -> None:
    headers = [(b"host", b"example.com:8080")]
    scope = create_scope(headers=headers)
    output = format_log("%({host}i)s", scope, 200, 0.123, 1024)
    assert output == "example.com:8080"


def test_request_header_atom_custom() -> None:
    headers = [(b"x-request-id", b"abc-123-def")]
    scope = create_scope(headers=headers)
    output = format_log("%({x-request-id}i)s", scope, 200, 0.123, 1024)
    assert output == "abc-123-def"


def test_request_header_atom_missing() -> None:
    scope = create_scope(headers=[])
    output = format_log("%({x-missing}i)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_response_header_atom() -> None:
    scope = create_scope()
    output = format_log("%({content-type}o)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_common_log_format() -> None:
    fmt = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s'
    scope = create_scope(method="GET", path="/test", query_string=b"")
    output = format_log(fmt, scope, 200, 0.123, 1024)

    assert "192.168.1.100" in output
    assert " - " in output
    assert "GET /test HTTP/1.1" in output
    assert " 200 " in output
    assert " 1024" in output


def test_combined_log_format() -> None:
    fmt = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
    headers = [
        (b"referer", b"http://example.com/"),
        (b"user-agent", b"TestClient/1.0"),
    ]
    scope = create_scope(headers=headers)
    output = format_log(fmt, scope, 200, 0.123, 1024)

    assert "192.168.1.100" in output
    assert "GET /test?foo=bar HTTP/1.1" in output
    assert " 200 " in output
    assert " 1024 " in output
    assert '"http://example.com/"' in output
    assert '"TestClient/1.0"' in output


def test_combined_format_with_basic_auth() -> None:
    fmt = '%(h)s - %(u)s [%(t)s] "%(r)s" %(s)s %(b)s'
    credentials = "api_user:api_key"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = [(b"authorization", f"Basic {encoded}".encode())]
    scope = create_scope(headers=headers)
    output = format_log(fmt, scope, 201, 0.456, 5678)

    assert "192.168.1.100 - api_user" in output
    assert " 201 " in output
    assert " 5678" in output


def test_custom_format_with_timing() -> None:
    fmt = "%(h)s [%(t)s] %(m)s %(U)s %(s)s %(D)s μs"
    scope = create_scope(method="POST", path="/api/users", query_string=b"")
    output = format_log(fmt, scope, 201, 0.123456, 2048)

    assert "192.168.1.100" in output
    assert "POST /api/users" in output
    assert " 201 " in output
    assert " 123456 μs" in output


def test_format_with_multiple_headers() -> None:
    fmt = "%(h)s %({host}i)s %({x-request-id}i)s %(s)s"
    headers = [
        (b"host", b"api.example.com"),
        (b"x-request-id", b"req-12345"),
    ]
    scope = create_scope(headers=headers)
    output = format_log(fmt, scope, 200, 0.123, 1024)

    assert "192.168.1.100" in output
    assert "api.example.com" in output
    assert "req-12345" in output
    assert " 200" in output


def test_no_client_address() -> None:
    scope = create_scope(client=None)
    output = format_log("%(h)s", scope, 200, 0.123, 1024)
    assert output == "-"


def test_ipv6_client_address() -> None:
    scope = create_scope(client=("::1", 54321))
    output = format_log("%(h)s", scope, 200, 0.123, 1024)
    assert output == "::1"


def test_various_http_methods() -> None:
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    for method in methods:
        scope = create_scope(method=method)
        output = format_log("%(m)s", scope, 200, 0.123, 1024)
        assert output == method


def test_various_status_codes() -> None:
    status_codes = [200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
    for status in status_codes:
        scope = create_scope()
        output = format_log("%(s)s", scope, status, 0.123, 1024)
        assert output == str(status)


def test_root_path() -> None:
    scope = create_scope(path="/", query_string=b"")
    output = format_log("%(U)s", scope, 200, 0.123, 1024)
    assert output == "/"


def test_complex_query_string() -> None:
    scope = create_scope(query_string=b"filter=active&sort=name&page=1&limit=50")
    output = format_log("%(q)s", scope, 200, 0.123, 1024)
    assert output == "filter=active&sort=name&page=1&limit=50"


def test_very_small_response_time() -> None:
    scope = create_scope()
    output = format_log("%(D)s", scope, 200, 0.000001, 1024)
    assert output == "1"


def test_very_large_response_time() -> None:
    scope = create_scope()
    output = format_log("%(T)s", scope, 200, 10.5, 1024)
    assert output == "10"


def test_large_response_size() -> None:
    scope = create_scope()
    output = format_log("%(B)s", scope, 200, 0.123, 10485760)  # 10MB
    assert output == "10485760"


def test_header_case_insensitive() -> None:
    headers = [
        (b"host", b"example.com"),
        (b"user-agent", b"TestClient"),
    ]
    scope = create_scope(headers=headers)
    output = format_log("%({Host}i)s %({USER-AGENT}i)s", scope, 200, 0.123, 1024)
    assert output == "example.com TestClient"


def test_missing_format_atom() -> None:
    scope = create_scope()
    output = format_log("%(x)s", scope, 200, 0.123, 1024)
    assert "<formatting error: missing atom" in output


def test_default_format() -> None:
    formatter = GunicornAccessFormatter(use_colors=False)
    scope = create_scope()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="",
        args=(scope, 200, 0.123, 1024),
        exc_info=None,
    )
    output = formatter.format(record)
    # Default format is Combined Log Format
    assert "192.168.1.100" in output
    assert "GET /test?foo=bar HTTP/1.1" in output
    assert " 200 " in output


def test_empty_headers_list() -> None:
    scope = create_scope(headers=[])
    output = format_log("%({host}i)s %(f)s %(a)s", scope, 200, 0.123, 1024)
    assert output == "- - -"


def test_none_response_time() -> None:
    scope = create_scope()
    output = format_log("%(T)s %(D)s %(M)s %(L)s", scope, 200, None, 1024)
    assert output == "0 0 0 0.000000"


def test_formatter_with_logger() -> None:
    formatter = GunicornAccessFormatter(
        fmt='%(h)s - %(u)s [%(t)s] "%(r)s" %(s)s %(b)s',
        use_colors=False,
    )

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/users",
        "query_string": b"page=1",
        "http_version": "1.1",
        "client": ("192.168.1.100", 12345),
        "headers": [(b"host", b"localhost")],
    }

    # Create a LogRecord directly since using logger.info() causes premature formatting
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="",
        args=(scope, 200, 0.123, 2048),
        exc_info=None,
    )

    output = formatter.format(record)

    assert "192.168.1.100" in output
    assert "- -" in output  # No basic auth
    assert '"GET /api/users?page=1 HTTP/1.1"' in output
    assert " 200 " in output
    assert " 2048" in output


def test_formatter_with_colors() -> None:
    """Test formatter with colors enabled."""
    formatter = GunicornAccessFormatter(fmt="%(r)s %(s)s", use_colors=True)
    scope = create_scope(method="POST", path="/test")

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="",
        args=(scope, 200, 0.123, 1024),
        exc_info=None,
    )

    output = formatter.format(record)
    # With colors, the request line and status should contain ANSI codes
    assert "POST /test?foo=bar HTTP/1.1" in output
    assert "200" in output


def test_get_status_code_colored() -> None:
    """Test get_status_code_colored method."""
    formatter = GunicornAccessFormatter(use_colors=True)

    # Test various status code ranges
    assert "200" in formatter.get_status_code_colored(200)
    assert "OK" in formatter.get_status_code_colored(200)

    assert "301" in formatter.get_status_code_colored(301)
    assert "Moved Permanently" in formatter.get_status_code_colored(301)

    assert "404" in formatter.get_status_code_colored(404)
    assert "Not Found" in formatter.get_status_code_colored(404)

    assert "500" in formatter.get_status_code_colored(500)
    assert "Internal Server Error" in formatter.get_status_code_colored(500)

    # Test unknown status code
    assert "599" in formatter.get_status_code_colored(599)


def test_get_status_code_colored_without_colors() -> None:
    """Test get_status_code_colored without colors."""
    formatter = GunicornAccessFormatter(use_colors=False)
    result = formatter.get_status_code_colored(200)
    assert result == "200 OK"
    # Should not contain ANSI escape codes
    assert "\x1b" not in result
