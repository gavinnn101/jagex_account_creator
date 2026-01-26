import base64
import selectors
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field
from typing import BinaryIO
from urllib.parse import urlparse

from loguru import logger

import models

END_OF_HEADER_DELIMITER = b"\r\n"
HTTP_VERSION = "HTTP/1.1"
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443


@dataclass(slots=True)
class Header:
    name: str
    value: str

    def __bytes__(self) -> bytes:
        return f"{self.name}: {self.value}".encode()


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    request_target: str
    http_version: str
    headers: tuple[Header, ...] = field(default_factory=tuple)

    @property
    def is_https(self) -> bool:
        return self.method == "CONNECT"

    def with_header(self, header: Header) -> "HttpRequest":
        """Return a new request with an additional header."""
        return HttpRequest(
            method=self.method,
            request_target=self.request_target,
            http_version=self.http_version,
            headers=(*self.headers, header),
        )

    def __bytes__(self) -> bytes:
        lines = [f"{self.method} {self.request_target} {self.http_version}".encode()]
        lines.extend(bytes(header) for header in self.headers)
        return END_OF_HEADER_DELIMITER.join(lines) + (END_OF_HEADER_DELIMITER * 2)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    http_version: str
    status_code: int
    status_reason: str = ""
    headers: tuple[Header, ...] = field(default_factory=tuple)

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def __bytes__(self) -> bytes:
        lines = [f"{self.http_version} {self.status_code} {self.status_reason}".encode()]
        lines.extend(bytes(header) for header in self.headers)
        return END_OF_HEADER_DELIMITER.join(lines) + (END_OF_HEADER_DELIMITER * 2)


class GProxy:
    __slots__ = (
        "ip",
        "port",
        "upstream_proxy",
        "upstream_proxy_auth_header",
        "allowed_hosts",
        "buffer_size",
        "tunnel_timeout",
        "_address",
        "_server_socket",
        "_executor",
        "_stopped",
    )

    def __init__(
        self,
        ip: str = "127.0.0.1",
        port: int | None = None,
        upstream_proxy: models.Proxy | None = None,
        allowed_hosts: list[str] | None = None,
        buffer_size: int = 65_536,
        tunnel_timeout: int = 30,
        max_threads: int = 100,
    ) -> None:
        self.ip = ip
        self.port = port if port is not None else self._find_free_port()
        self._address = (self.ip, self.port)
        self._server_socket = self._create_server_socket()

        self.upstream_proxy = upstream_proxy
        self.upstream_proxy_auth_header = self._build_proxy_auth_header()

        self.allowed_hosts = allowed_hosts
        self.buffer_size = buffer_size
        self.tunnel_timeout = tunnel_timeout

        self._executor = ThreadPoolExecutor(max_workers=max_threads)
        self._stopped = threading.Event()

    def _find_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.ip, 0))
            return sock.getsockname()[1]

    def _create_server_socket(self) -> socket.socket:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(0.1)
        server_socket.bind(self._address)
        return server_socket

    def _is_host_allowed(self, host: str) -> bool:
        if not self.allowed_hosts:
            return True
        return any(pattern in host for pattern in self.allowed_hosts)

    def _build_proxy_auth_header(self) -> Header | None:
        if not self.upstream_proxy:
            return None
        if not (self.upstream_proxy.username and self.upstream_proxy.password):
            return None

        credentials = f"{self.upstream_proxy.username}:{self.upstream_proxy.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return Header(name="Proxy-Authorization", value=f"Basic {encoded}")

    @staticmethod
    def _read_headers(reader: BinaryIO) -> tuple[Header, ...]:
        headers: list[Header] = []
        while line := reader.readline().rstrip(END_OF_HEADER_DELIMITER):
            name, value = line.decode().split(": ", 1)
            headers.append(Header(name=name, value=value))
        return tuple(headers)

    def _read_request(self, reader: BinaryIO) -> HttpRequest:
        logger.debug("Reading request from socket.")

        line = reader.readline().rstrip(END_OF_HEADER_DELIMITER)
        method, request_target, http_version = line.decode().split()

        return HttpRequest(
            method=method,
            request_target=request_target,
            http_version=http_version,
            headers=self._read_headers(reader),
        )

    def _read_response(self, reader: BinaryIO) -> HttpResponse:
        logger.debug("Reading response from socket.")

        line = reader.readline().rstrip(END_OF_HEADER_DELIMITER)
        data_string = line.decode()
        logger.debug(f"Response status line: {data_string}")

        # Handle responses with or without reason phrase
        parts = data_string.split(maxsplit=2)
        http_version = parts[0]
        status_code = int(parts[1])
        status_reason = parts[2] if len(parts) > 2 else ""

        return HttpResponse(
            http_version=http_version,
            status_code=status_code,
            status_reason=status_reason,
            headers=self._read_headers(reader),
        )

    def _establish_proxy_tunnel(
        self, destination_socket: socket.socket, host: str, port: int
    ) -> bool:
        logger.debug("Establishing proxy tunnel for https connection.")

        headers = [Header(name="Host", value=f"{host}:{port}")]
        if self.upstream_proxy_auth_header:
            headers.append(self.upstream_proxy_auth_header)

        request = HttpRequest(
            method="CONNECT",
            request_target=f"{host}:{port}",
            http_version=HTTP_VERSION,
            headers=tuple(headers),
        )

        logger.debug(f"Sending request header: {bytes(request)}")
        destination_socket.sendall(bytes(request))

        with destination_socket.makefile("rb") as reader:
            response = self._read_response(reader=reader)

        logger.debug(f"Got response: {response}")
        return response.is_success

    def _tunnel_data(self, client_socket: socket.socket, destination_socket: socket.socket) -> None:
        logger.debug("Tunneling data between sockets.")

        client_socket.setblocking(False)
        destination_socket.setblocking(False)

        sel = selectors.DefaultSelector()
        try:
            sel.register(client_socket, selectors.EVENT_READ, destination_socket)
            sel.register(destination_socket, selectors.EVENT_READ, client_socket)
            self._run_tunnel_loop(sel)
        finally:
            sel.close()

    def _run_tunnel_loop(self, sel: selectors.DefaultSelector) -> None:
        while events := sel.select(timeout=self.tunnel_timeout):
            for key, _ in events:
                src_socket: socket.socket = key.fileobj
                dst_socket: socket.socket = key.data

                data = src_socket.recv(self.buffer_size)
                if not data:
                    return

                dst_socket.sendall(data)

    def _parse_destination(self, request: HttpRequest) -> tuple[str, int]:
        """Extract host and port from the request."""
        if request.is_https:
            host, port_str = request.request_target.split(":")
            return host, int(port_str)

        parsed_url = urlparse(request.request_target)
        return parsed_url.hostname, parsed_url.port or DEFAULT_HTTP_PORT

    def _handle_request(self, client_socket: socket.socket) -> None:
        logger.debug(f"Handling socket: {client_socket}")
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        with client_socket.makefile("rb") as reader:
            request = self._read_request(reader=reader)
        logger.debug(f"Got request: {request}")

        host, port = self._parse_destination(request)

        if not self._is_host_allowed(host):
            logger.debug(f"Blocked request to host: {host}")
            return

        destination_socket = self._connect_to_destination(host, port)
        if not destination_socket:
            return

        try:
            self._process_connection(client_socket, destination_socket, request, host, port)
        finally:
            destination_socket.close()

    def _connect_to_destination(self, host: str, port: int) -> socket.socket | None:
        """Create connection to destination (direct or via upstream proxy)."""
        address = (
            (self.upstream_proxy.ip, self.upstream_proxy.port)
            if self.upstream_proxy
            else (host, port)
        )
        return socket.create_connection(address=address, timeout=self.tunnel_timeout)

    def _process_connection(
        self,
        client_socket: socket.socket,
        destination_socket: socket.socket,
        request: HttpRequest,
        host: str,
        port: int,
    ) -> None:
        """Process the connection based on request type (HTTPS tunnel or HTTP forward)."""
        if request.is_https:
            if not self._handle_https_connection(client_socket, destination_socket, host, port):
                return
        else:
            self._handle_http_connection(destination_socket, request)

        self._tunnel_data(client_socket, destination_socket)

    def _handle_https_connection(
        self,
        client_socket: socket.socket,
        destination_socket: socket.socket,
        host: str,
        port: int,
    ) -> bool:
        """Handle HTTPS CONNECT request. Returns True if tunnel established successfully."""
        if self.upstream_proxy:
            if not self._establish_proxy_tunnel(destination_socket, host, port):
                logger.error("Failed to establish proxy tunnel!")
                return False

        response = HttpResponse(
            http_version=HTTP_VERSION,
            status_code=200,
            status_reason="Connection Established",
        )
        logger.debug(f"Sending connection established response: {response}")
        client_socket.sendall(bytes(response))
        return True

    def _handle_http_connection(
        self, destination_socket: socket.socket, request: HttpRequest
    ) -> None:
        """Forward HTTP request, adding proxy auth header if needed."""
        if self.upstream_proxy_auth_header:
            request = request.with_header(self.upstream_proxy_auth_header)
        destination_socket.sendall(bytes(request))

    def _safe_handle_request(self, client_socket: socket.socket) -> None:
        try:
            self._handle_request(client_socket)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            if not self._stopped.is_set():
                logger.debug(f"Request handler error: {e}")
        finally:
            with suppress(Exception):
                client_socket.close()

    def _handle_requests(self) -> None:
        while not self._stopped.is_set():
            try:
                client_socket, _ = self._server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            if client_socket:
                self._executor.submit(self._safe_handle_request, client_socket)

    def start(self) -> None:
        logger.info(f"Starting proxy server at {self.ip}:{self.port}")
        self._stopped.clear()

        if self._server_socket.fileno() == -1:
            self._server_socket = self._create_server_socket()

        self._server_socket.listen()
        threading.Thread(target=self._handle_requests, daemon=True).start()

    def stop(self) -> None:
        logger.info(f"Stopping proxy server at {self.ip}:{self.port}")
        self._stopped.set()
        self._server_socket.close()
        self._executor.shutdown(wait=False, cancel_futures=True)
