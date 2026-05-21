from __future__ import annotations

import ipaddress
from typing import Literal

from uvicorn._types import ASGI3Application, ASGIReceiveCallable, ASGISendCallable, Scope, WWWScope


class ProxyHeadersMiddleware:
    """Maps proxy-supplied forwarding headers onto the ASGI scope.

    Selects a parser at construction based on `mode`:

    * `"x-forwarded"` (default) - reads `X-Forwarded-Proto`, `X-Forwarded-For`,
      and `X-Forwarded-Host`.
    * `"forwarded"` - reads the standardized `Forwarded` header (RFC 7239).

    Modes are mutually exclusive: when one is selected, the other family is
    ignored entirely. Silent fallback would let an attacker set whichever
    family the proxy is not configured for.
    """

    def __init__(
        self,
        app: ASGI3Application,
        trusted_hosts: list[str] | str = "127.0.0.1",
        mode: Literal["x-forwarded", "forwarded"] = "x-forwarded",
    ) -> None:
        trusted = _TrustedHosts(trusted_hosts)
        self._inner = (_XForwardedParser if mode == "x-forwarded" else _RFC7239Parser)(app, trusted)

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        return await self._inner(scope, receive, send)


class _BaseForwardedParser:
    """Base parser: handles trust gating and shared scope rewriting.

    Subclasses implement `apply`, which is invoked only when the connecting peer is in the trust set.
    """

    def __init__(self, app: ASGI3Application, trusted: _TrustedHosts) -> None:
        self.app = app
        self.trusted = trusted

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] != "lifespan":
            client_addr = scope.get("client")
            client_host = client_addr[0] if client_addr else None
            if client_host in self.trusted:
                self.apply(scope)
        return await self.app(scope, receive, send)

    def apply(self, scope: WWWScope) -> None:
        raise NotImplementedError

    @staticmethod
    def set_scheme(scope: WWWScope, proto: str) -> None:
        if proto not in {"http", "https", "ws", "wss"}:
            return
        if scope["type"] == "websocket":
            scope["scheme"] = proto.replace("http", "ws")
        else:
            scope["scheme"] = proto

    @staticmethod
    def set_host(scope: WWWScope, host_value: str) -> None:
        # Rewrite only the `Host` header. Per ASGI, `scope["server"]` is the local bind
        # address, not the client-perceived host, so we leave it untouched.
        scope["headers"] = [(name, value) for name, value in scope["headers"] if name != b"host"] + [
            (b"host", host_value.encode("latin1"))
        ]


class _XForwardedParser(_BaseForwardedParser):
    """Reads the `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Forwarded-Host` family."""

    def apply(self, scope: WWWScope) -> None:
        if (proto := _last_field(scope, b"x-forwarded-proto")) is not None:
            self.set_scheme(scope, proto.strip())

        if (forwarded_for := _join_field(scope, b"x-forwarded-for")) is not None:
            host, port = self.trusted.get_trusted_client_address(forwarded_for)
            if host:
                # Empty x-forwarded-for yields an empty host - skip in that case.
                # See: https://github.com/Kludex/uvicorn/issues/1068
                scope["client"] = (host, port)

        if (forwarded_host := _last_field(scope, b"x-forwarded-host")) is not None:
            if (value := forwarded_host.strip()) != "":
                self.set_host(scope, value)


class _RFC7239Parser(_BaseForwardedParser):
    """Reads the standardized `Forwarded` header (RFC 7239)."""

    def apply(self, scope: WWWScope) -> None:
        if (forwarded := _join_field(scope, b"forwarded")) is None:
            return

        entry = self.trusted.get_trusted_forwarded_entry(forwarded)
        if entry is None:
            return

        if (proto := entry.get("proto")) is not None:
            self.set_scheme(scope, proto.lower())

        # `for=` is guaranteed present and non-placeholder by `get_trusted_forwarded_entry`.
        host, port = _parse_host_port(entry["for"])
        if host:
            scope["client"] = (host, port)

        if (forwarded_host := entry.get("host")) is not None and forwarded_host != "":
            self.set_host(scope, forwarded_host)


def _join_field(scope: WWWScope, name: bytes) -> str | None:
    """Concatenate all occurrences of a list-valued header field in wire order.

    Per RFC 7230 §3.2.2 and RFC 7239 §7.1, list-valued header fields may appear
    multiple times in the message and are equivalent to a single field with a
    comma-joined value. `dict(scope["headers"])` would keep only one
    occurrence and is unsafe for these fields.
    """
    values = [value.decode("latin1") for n, value in scope["headers"] if n == name]
    if not values:
        return None
    return ", ".join(values)


def _last_field(scope: WWWScope, name: bytes) -> str | None:
    """Return the last occurrence of a single-valued header field.

    `X-Forwarded-Proto` and `X-Forwarded-Host` are de-facto single-valued
    headers; if the message contains repeats, the rightmost is the value
    appended by the trusted upstream proxy (nginx, Apache, ALB and friends
    all append rather than prepend). Picking the leftmost would let an
    attacker preserve a client-supplied value past a proxy. This also
    matches the prior uvicorn behavior, which used `dict(scope["headers"])`
    and effectively kept the last value.
    """
    result: str | None = None
    for n, value in scope["headers"]:
        if n == name:
            result = value.decode("latin1")
    return result


def _is_placeholder_for(value: str) -> bool:
    """RFC 7239 placeholder identifiers: `unknown` (case-insensitive) or obfuscated `_*`."""
    return value.lower() == "unknown" or value.startswith("_")


def _parse_raw_hosts(value: str) -> list[str]:
    return [item.strip() for item in value.split(",")]


def _parse_host_port(value: str) -> tuple[str, int]:
    """Parse a forwarded host value into host and optional port.

    Accepts bare IPs, IPv4 `host:port`, and bracketed IPv6 `[host]:port`.
    Any unrecognized or malformed value is returned without a port so trust
    checks do not silently normalize arbitrary input.
    """

    if value.startswith("["):
        bracket_end = value.find("]")
        if bracket_end == -1:
            return value, 0

        host = value[1:bracket_end]
        remainder = value[bracket_end + 1 :]
        if not remainder:
            return host, 0
        if not remainder.startswith(":"):
            return value, 0

        try:
            return host, int(remainder[1:])
        except ValueError:
            return host, 0

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return value, 0

    return value, 0


def _parse_forwarded(value: str) -> list[dict[str, str]]:
    """Parse an RFC 7239 `Forwarded` header into a list of hop dicts.

    Each entry maps lowercase parameter names (`for`, `host`, `proto`,
    `by`) to their (unquoted) values. Unrecognized parameters are dropped;
    malformed pairs are skipped without raising. Per RFC 7239 §4 each
    parameter must occur at most once per forwarded-element; entries that
    violate this are discarded entirely to avoid header smuggling.
    """

    entries: list[dict[str, str]] = []
    for raw_entry in _split_outside_quotes(value, ","):
        params: dict[str, str] = {}
        duplicate = False
        for raw_pair in _split_outside_quotes(raw_entry, ";"):
            name, sep, val = raw_pair.strip().partition("=")
            if not sep:
                continue
            key = name.strip().lower()
            if key in {"for", "host", "proto", "by"}:
                if key in params:
                    duplicate = True
                    break
                params[key] = _unquote(val.strip())
        if params and not duplicate:
            entries.append(params)
    return entries


def _split_outside_quotes(value: str, separator: str) -> list[str]:
    """Split `value` on `separator` while respecting RFC 7230 quoted-strings."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and in_quotes and i + 1 < len(value):
            current.append(value[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == separator and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def _unquote(value: str) -> str:
    """Strip surrounding quotes and unescape backslash sequences (RFC 7230)."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        result: list[str] = []
        i = 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                result.append(inner[i + 1])
                i += 2
            else:
                result.append(inner[i])
                i += 1
        return "".join(result)
    return value


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

    def get_trusted_client_address(self, x_forwarded_for: str) -> tuple[str, int]:
        """Extract the client address from x_forwarded_for header.

        In general this is the first "untrusted" host in the forwarded for list.
        """
        x_forwarded_for_hosts = _parse_raw_hosts(x_forwarded_for)

        if self.always_trust:
            return _parse_host_port(x_forwarded_for_hosts[0])

        # Note: each proxy appends to the header list so check it in reverse order
        for host_port in reversed(x_forwarded_for_hosts):
            host, port = _parse_host_port(host_port)
            if host not in self:
                return host, port

        # All hosts are trusted meaning that the client was also a trusted proxy
        # See https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
        return _parse_host_port(x_forwarded_for_hosts[0])

    def get_trusted_forwarded_entry(self, forwarded: str) -> dict[str, str] | None:
        """Extract the trusted hop entry from an RFC 7239 `Forwarded` header.

        Mirrors `get_trusted_client_address`: walk hops from right and
        return the first one whose `for=` is set, anchorable, and not in
        the trust set. Entries with no `for=` or with placeholder values
        (`unknown`, `_obfuscated`) cannot establish the client hop and
        are filtered out before selection - returning one would attach a
        stale `host=`/`proto=` to the request without a verifiable client.
        Returns `None` when no anchorable hop exists.
        """

        anchorable = [
            entry
            for entry in _parse_forwarded(forwarded)
            if (for_ := entry.get("for")) is not None and not _is_placeholder_for(for_)
        ]
        if not anchorable:
            return None

        if self.always_trust:
            return anchorable[0]

        for entry in reversed(anchorable):
            host, _ = _parse_host_port(entry["for"])
            if host not in self:
                return entry

        # All anchorable hops were trusted - fall back to the leftmost
        # (original client, mirroring `get_trusted_client_address`).
        return anchorable[0]
