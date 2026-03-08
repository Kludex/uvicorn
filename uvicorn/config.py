import logging
import os
import ssl
import sys
from typing import Any, Callable, Dict, List, Optional, Union

import click

from uvicorn.importer import import_from_string
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.middleware.wsgi import WSGIMiddleware
from uvicorn.protocols.utils import get_-ssl_context


class Config:
    def __init__(
        self,
        app: Union[str, Callable[[Any, Any, Any], Any]],
        host: str = "127.0.0.1",
        port: int = 8000,
        ssl_keyfile: Optional[str] = None,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile_password: Optional[str] = None,
        ssl_version: int = ssl.PROTOCOL_TLS_SERVER,
        ssl_cert_reqs: int = ssl.CERT_NONE,
        ssl_ca_certs: Optional[str] = None,
        ssl_ciphers: str = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDSA+AESGCM:ECDSA+CHACHA20:RSA+AESGCM:RSA+CHACHA20",
        ssl_context: Optional[ssl.SSLContext] = None,
        headers: Optional[List[tuple[str, str]]] = None,
        # ... (rest of implementation)
    ):
        self.ssl_context = ssl_context
        # ... (assign existing fields)

    @property
    def is_ssl(self) -> bool:
        return bool(self.ssl_keyfile or self.ssl_certfile or self.ssl_context)

    def load_ssl(self) -> None:
        if self.ssl_context:
            self.ssl = self.ssl_context
        elif self.is_ssl:
            self.ssl = get_ssl_context(
                keyfile=self.ssl_keyfile,
                certfile=self.ssl_certfile,
                keyfile_password=self.ssl_keyfile_password,
                ssl_version=self.ssl_version,
                cert_reqs=self.ssl_cert_reqs,
                ca_certs=self.ssl_ca_certs,
                ciphers=self.ssl_ciphers,
            )
        else:
            self.ssl = None
