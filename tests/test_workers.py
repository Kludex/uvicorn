import logging

import pytest


@pytest.mark.filterwarnings("ignore:The `uvicorn.workers` module is deprecated:DeprecationWarning")
def test_gunicorn_access_formatter_honors_access_log_format() -> None:
    from uvicorn.workers import GunicornAccessFormatter

    formatter = GunicornAccessFormatter('%(h)s %(m)s %(U)s %(q)s %(s)s "%(a)s"')
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:12345", "GET", "/hello?name=uvicorn", "1.1", 204),
        exc_info=None,
    )

    assert formatter.format(record) == '127.0.0.1 GET /hello name=uvicorn 204 "-"'


@pytest.mark.filterwarnings("ignore:The `uvicorn.workers` module is deprecated:DeprecationWarning")
def test_gunicorn_access_formatter_leaves_non_uvicorn_records_unchanged() -> None:
    from uvicorn.workers import GunicornAccessFormatter

    formatter = GunicornAccessFormatter("%(h)s %(r)s %(s)s")
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="already formatted",
        args=(),
        exc_info=None,
    )

    assert formatter.format(record) == "already formatted"
