from typing import Any, Dict, Type

import pytest
from gunicorn.app.base import BaseApplication
from gunicorn.arbiter import Arbiter
from gunicorn.workers.base import Worker

from uvicorn.workers import UvicornH11Worker, UvicornWorker


async def app(scope, receive, send):
    ...


class Application(BaseApplication):
    def __init__(self, application, options: Dict[str, Any]):
        self.options = options or {}
        self.application = application
        super().__init__()

    def init(self, parser, opts, args):
        """No-op"""

    def load(self):
        return self.application

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)


@pytest.mark.parametrize(
    "worker_class_path, worker_class",
    [
        ("uvicorn.workers.UvicornWorker", UvicornWorker),
        ("uvicorn.workers.UvicornH11Worker", UvicornH11Worker),
    ],
)
def test_worker(worker_class_path: str, worker_class: Type[Worker]) -> None:
    arbiter = Arbiter(
        Application(
            app,
            {
                "worker_class": worker_class_path,
                "bind": "0.0.0.0:0",
                "graceful_timeout": 0,
            },
        ),
    )
    arbiter.start()
    pid = arbiter.spawn_worker()
    assert arbiter.worker_class == worker_class
    worker = arbiter.WORKERS[pid]
    assert isinstance(worker, worker_class)
    assert len(arbiter.LISTENERS) == 1
    arbiter.stop()
    assert arbiter.LISTENERS == []
