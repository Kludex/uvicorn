from __future__ import annotations

import ipaddress

from uvicorn._types import ASGI3Application, ASGIReceiveCallable, ASGISendCallable, Scope


class ProxyHeadersMiddleware:
    """Middleware for handling known proxy headers

    This middleware can be used when a known proxy is fronting the application,
    and is trusted to be properly setting the `X-Forwarded-Proto` and
    `X-Forwarded-For` headers with the connecting client information.

    Modifies the `client` and `scheme` information so that they reference
    the connecting client, rather that the connecting proxy.

    References:
    - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#Proxies>
    - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For>
    """

    def __init__(self, app: ASGI3Application, trusted_hosts: list[str] | str = "127.0.0.1") -> None:
        self.app = app
        self.trusted_hosts = _TrustedHosts(trusted_hosts)

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)

        client_addr = scope.get("client")
        client_host = client_addr[0] if client_addr else None

        if client_host in self.trusted_hosts:
            headers = dict(scope["headers"])

            if b"x-forwarded-proto" in headers:
                x_forwarded_proto = headers[b"x-forwarded-proto"].decode("latin1").strip()

                if x_forwarded_proto in {"http", "https", "ws", "wss"}:
                    if scope["type"] == "websocket":
                        scope["scheme"] = x_forwarded_proto.replace("http", "ws")
                    else:
                        scope["scheme"] = x_forwarded_proto

            if b"x-forwarded-for" in headers:
                x_forwarded_for = headers[b"x-forwarded-for"].decode("latin1")
                host = self.trusted_hosts.get_trusted_client_host(x_forwarded_for)

                if host:
                    # If the x-forwarded-for header is empty then host is an empty string.
                    # Only set the client if we actually got something usable.
                    # See: https://github.com/Kludex/uvicorn/issues/1068

                    # The host may include a port (e.g. "1.2.3.4:8080").
                    # Parse it out so we don't produce malformed client tuples.
                    addr, port = _parse_host_and_port(host)
                    scope["client"] = (addr, port)

        return await self.app(scope, receive, send)


def _parse_raw_hosts(value: str) -> list[str]:
    return [item.strip() for item in value.split(",")]


def _parse_host_and_port(host: str) -> tuple[str, int]:
    """Parse a host string that may include a port number.

    Handles IPv4 (``1.2.3.4:8080``), bracketed IPv6 (``[::1]:8080``),
    and bare hosts without a port.  Returns ``(host, port)`` where *port*
    is ``0`` when not present.
    """
    if host.startswith("["):
        # Bracketed IPv6, e.g. [::1]:8080
        bracket_end = host.find("]")
        if bracket_end == -1:
            return host, 0
        ip_part = host[1:bracket_end]
        remainder = host[bracket_end + 1 :]
        if remainder.startswith(":"):
            try:
                return ip_part, int(remainder[1:])
            except ValueError:
                return ip_part, 0
        return ip_part, 0

    # IPv4 or hostname — only treat as host:port if there's exactly one colon
    if host.count(":") == 1:
        addr, _, port_str = host.partition(":")
        try:
            return addr, int(port_str)
        except ValueError:
            return host, 0

    return host, 0


class _TrustedHosts:
    """Container for trusted hosts and networks"""

    def __init__(self, trusted_hosts: list[str] | str) -> None:
        self.always_trust: bool = trusted_hosts in ("*", ["*"])

        self.trusted_literals: set[str] = set()
        self.trusted_hosts: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self.trusted_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()

        # Notes:
        # - We separate hosts from literals as there are many ways to write
        #   an IPv6 Address so we need to compare by object.
        # - We don't convert IP Address to single host networks (e.g. /32 / 128) as
        #   it more efficient to do an address lookup in a set than check for
        #   membership in each network.
        # - We still allow literals as it might be possible that we receive a
        #   something that isn't an IP Address e.g. a unix socket.

        if not self.always_trust:
            if isinstance(trusted_hosts, str):
                trusted_hosts = _parse_raw_hosts(trusted_hosts)

            for host in trusted_hosts:
                # Note: because we always convert invalid IP types to literals it
                # is not possible for the user to know they provided a malformed IP
                # type - this may lead to unexpected / difficult to debug behaviour.

                if "/" in host:
                    # Looks like a network
                    try:
                        self.trusted_networks.add(ipaddress.ip_network(host))
                    except ValueError:
                        # Was not a valid IP Network
                        self.trusted_literals.add(host)
                else:
                    try:
                        self.trusted_hosts.add(ipaddress.ip_address(host))
                    except ValueError:
                        # Was not a valid IP Address
                        self.trusted_literals.add(host)

    def __contains__(self, host: str | None) -> bool:
        if self.always_trust:
            return True

        if not host:
            return False

        try:
            ip = ipaddress.ip_address(host)
            if ip in self.trusted_hosts:
                return True
            return any(ip in net for net in self.trusted_networks)

        except ValueError:
            return host in self.trusted_literals

    def get_trusted_client_host(self, x_forwarded_for: str) -> str:
        """Extract the client host from x_forwarded_for header

        In general this is the first "untrusted" host in the forwarded for list.
        """
        x_forwarded_for_hosts = _parse_raw_hosts(x_forwarded_for)

        if self.always_trust:
            return x_forwarded_for_hosts[0]

        # Note: each proxy appends to the header list so check it in reverse order
        for host in reversed(x_forwarded_for_hosts):
            addr, _ = _parse_host_and_port(host)
            if addr not in self:
                return host

        # All hosts are trusted meaning that the client was also a trusted proxy
        # See https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
        return x_forwarded_for_hosts[0]
