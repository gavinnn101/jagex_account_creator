import base64
import select
import socket
import threading
from urllib.parse import urlparse

from loguru import logger

from models import Proxy


class GProxy:
    _TUNNEL_TIMEOUT = 10

    def __init__(
        self,
        ip: str = "127.0.0.1",
        port: int | None = None,
        buffer_size: int = 65_536,
        upstream_proxy: Proxy | None = None,
        allowed_url_patterns: list[str] | None = None,
    ):
        self.ip = ip
        self.port = port or self._find_free_port()
        self._address = (self.ip, self.port)

        self.upstream_proxy = upstream_proxy
        self.allowed_url_patterns = allowed_url_patterns

        self.buffer_size = buffer_size
        self._server_socket = self._create_server_socket()

        self._stopped = threading.Event()

    def _create_server_socket(self) -> socket.socket:
        """Create a socket to use for the proxy server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(1)
        server_socket.bind(self._address)
        return server_socket

    def is_server_socket_closed(self) -> bool:
        """Check if the current server socket is closed."""
        return self._server_socket.fileno() == -1

    def _find_free_port(self) -> int:
        """Find a free port to use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.ip, 0))
            return s.getsockname()[1]

    def _read_until_headers_complete(self, sock: socket.socket, initial_data: bytes = b"") -> bytes:
        """Read until we see the end of HTTP headers."""
        data = initial_data
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(self.buffer_size)
            if not chunk:
                break
            data += chunk
        return data

    def _extract_host_port_from_request(self, request: bytes) -> tuple[str, int]:
        """Extract the host and port from a request."""
        lines = request.decode(errors="ignore").split("\r\n")
        request_line = lines[0]
        _, url, _ = request_line.split()

        parsed_url = urlparse(url)
        if parsed_url.hostname:
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            return host, port

        host_header = next((line for line in lines if line.lower().startswith("host:")), None)
        if host_header:
            host_string = host_header.split(":", 1)[1].strip()
            if ":" in host_string:
                host, port_str = host_string.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_string
                port = 80
            return host, port
        raise ValueError("Could not extract host/port from request")

    def tunnel_data(self, client_socket: socket.socket, destination_socket: socket.socket) -> None:
        """Tunnel data between a client and destination socket."""
        client_socket.setblocking(False)
        destination_socket.setblocking(False)

        sockets = [client_socket, destination_socket]

        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, self._TUNNEL_TIMEOUT)

            if exceptional or not readable:
                break

            for src_socket in readable:
                data = src_socket.recv(self.buffer_size)
                if not data:
                    return

                dst_socket = destination_socket if src_socket is client_socket else client_socket
                dst_socket.sendall(data)

    def _build_proxy_auth_header(self) -> str:
        """Build the Proxy-Authorization header if credentials are configured."""
        if self.upstream_proxy and self.upstream_proxy.username and self.upstream_proxy.password:
            credentials = f"{self.upstream_proxy.username}:{self.upstream_proxy.password}"
            return (
                f"Proxy-Authorization: Basic {base64.b64encode(credentials.encode()).decode()}\r\n"
            )
        return ""

    def _connect_to_destination(self, host: str, port: int) -> socket.socket:
        """Connect to the destination, either directly or via upstream proxy."""
        if self.upstream_proxy:
            target = (self.upstream_proxy.ip, self.upstream_proxy.port)
        else:
            target = (host, port)

        sock = socket.create_connection(target, timeout=5)
        return sock

    def _establish_upstream_tunnel(self, dest_socket: socket.socket, host: str, port: int) -> None:
        """Send CONNECT to upstream proxy and verify success."""
        proxy_auth = self._build_proxy_auth_header()
        connect_request = (
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{proxy_auth}\r\n"
        ).encode()
        dest_socket.sendall(connect_request)

        proxy_response = self._read_until_headers_complete(dest_socket)
        status_line = proxy_response.split(b"\r\n")[0]
        if b"200" not in status_line:
            raise Exception(f"Proxy CONNECT failed: {status_line.decode()}")

    def _rewrite_request_for_upstream(self, request_data: bytes, host: str, port: int) -> bytes:
        """Rewrite an HTTP request to go through the upstream proxy."""
        proxy_auth = self._build_proxy_auth_header()

        req_line, headers = request_data.split(b"\r\n", 1)
        method, path, version = req_line.decode().split()

        if not path.startswith(("http://", "https://")):
            path = f"http://{host}:{port}{path}"

        return f"{method} {path} {version}\r\n".encode() + proxy_auth.encode() + headers

    def _handle_request(self, client_socket: socket.socket) -> None:
        """Handle the incoming socket request data."""
        destination_socket = None

        initial_chunk = client_socket.recv(self.buffer_size)
        if not initial_chunk:
            return

        request_line = initial_chunk.split(b"\r\n", 1)[0].decode()
        method, url, _ = request_line.split()
        is_https = method == "CONNECT"

        if is_https:
            host, port_str = url.split(":")
            port = int(port_str)
        else:
            request_data = self._read_until_headers_complete(client_socket, initial_chunk)
            host, port = self._extract_host_port_from_request(request_data)

        destination_socket = self._connect_to_destination(host, port)

        if is_https:
            if self.upstream_proxy:
                self._establish_upstream_tunnel(destination_socket, host, port)
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            if self.upstream_proxy:
                request_data = self._rewrite_request_for_upstream(request_data, host, port)
            destination_socket.sendall(request_data)

        if self.allowed_url_patterns and not any(
            pattern in host for pattern in self.allowed_url_patterns
        ):
            logger.debug(f"Blocking request from host: {host}")
            return

        self.tunnel_data(client_socket, destination_socket)

        if destination_socket:
            destination_socket.close()

    def _safe_handle_request(self, client_socket: socket.socket) -> None:
        """Wrapper to catch exceptions during request handling."""
        try:
            self._handle_request(client_socket)
        except (ConnectionAbortedError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            if not self._stopped.is_set():
                logger.debug(f"Request handler error: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _handle_requests(self) -> None:
        """Run the main loop to handle incoming requests."""
        while not self._stopped.is_set():
            try:
                client_socket, addr = self._server_socket.accept()
            except Exception:
                continue

            threading.Thread(
                target=self._safe_handle_request, args=(client_socket,), daemon=True
            ).start()

    def start(self) -> None:
        """Start the proxy server in its own thread."""
        logger.info(f"Starting gproxy server at address: {self._address}")
        self._stopped.clear()
        if self.is_server_socket_closed():
            self._server_socket = self._create_server_socket()
        self._server_socket.listen()
        threading.Thread(target=self._handle_requests, daemon=True).start()

    def stop(self) -> None:
        """Stop the proxy server."""
        logger.info(f"Stopping gproxy server at address: {self._address}")
        self._stopped.set()
        self._server_socket.close()
