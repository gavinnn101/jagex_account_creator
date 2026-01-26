import base64
import select
import socket
import sys
import threading
from urllib.parse import urlparse

from loguru import logger

from proxy import Proxy


class TrafficFilterProxy:
    def __init__(
        self,
        ip: str = "127.0.0.1",
        port: int = None,
        allowed_url_patterns: list[str] = None,
        upstream_proxy: Proxy | None = None,
    ):
        self.ip = ip
        self.port = port or self._find_free_port()
        self.address = (self.ip, self.port)

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(1.0)
        self.data_transfer_size = 8192

        self.server.bind(self.address)
        self.server.listen(10)

        self.allowed_url_patterns = allowed_url_patterns

        self.upstream_proxy = upstream_proxy

        self.running = False
        self.thread = None

    def _find_free_port(self) -> int:
        """Find a free port to use"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.ip, 0))
            return s.getsockname()[1]

    def get_request_data(self, client_socket: socket.socket) -> bytes:
        """Receive and return all data from a request on the socket."""
        request_data = b""
        client_socket.settimeout(1.0)
        while True:
            try:
                data = client_socket.recv(self.data_transfer_size)
                request_data += data
            except Exception:
                break
        return request_data

    def extract_host_port_from_request(self, request: bytes) -> tuple[str, int]:
        lines = request.decode(errors="ignore").split("\r\n")
        request_line = lines[0]
        method, url, _ = request_line.split()

        # First, try parsing host and port directly from the request line (absolute URL)
        parsed_url = urlparse(url)
        if parsed_url.hostname:
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            return host, port

        # If not absolute URL, fall back to the Host header
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

        raise ValueError("Host header missing and no absolute URL in request line.")

    def handle_client_request(self, client_socket: socket.socket) -> None:
        """Receives the client request and handles it appropriately."""
        logger.debug("Handling client request.")
        destination_socket = None
        try:
            first_chunk = client_socket.recv(4096)
            if not first_chunk:
                return

            request_line = first_chunk.split(b"\r\n", 1)[0].decode()
            method, target, _ = request_line.split()
            is_https = method == "CONNECT"

            if is_https:
                host, port = target.split(":")
                port = int(port)
                request_data = first_chunk
            else:
                request_data = (
                    first_chunk
                    if b"\r\n\r\n" in first_chunk
                    else first_chunk + self.get_request_data(client_socket)
                )
                host, port = self.extract_host_port_from_request(request_data)

            logger.debug(f"Host: {host}, Port: {port}, HTTPS: {is_https}")

            if self.allowed_url_patterns and not any(
                pat in host for pat in self.allowed_url_patterns
            ):
                client_socket.close()
                return

            destination_socket = socket.create_connection(
                (self.upstream_proxy.ip, self.upstream_proxy.port)
                if self.upstream_proxy
                else (host, port),
                timeout=5,
            )

            proxy_auth = ""
            if self.upstream_proxy:
                username = self.upstream_proxy.username
                password = self.upstream_proxy.password
                if username and password:
                    credentials = f"{username}:{password}"
                    proxy_auth = f"Proxy-Authorization: Basic {base64.b64encode(credentials.encode()).decode()}\r\n"

            if is_https:
                if self.upstream_proxy:
                    connect_request = (
                        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{proxy_auth}\r\n"
                    ).encode()
                    destination_socket.sendall(connect_request)
                    proxy_response = self.get_request_data(destination_socket)
                    if b"200" not in proxy_response.split(b"\r\n")[0]:
                        raise Exception("Proxy CONNECT failed")
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                logger.debug(f"Tunnel established for {host}:{port}")
                self.tunnel_data(client_socket, destination_socket)
            else:
                if self.upstream_proxy:
                    req_line, headers = request_data.split(b"\r\n", 1)
                    method, path, version = req_line.decode().split()
                    if not path.startswith(("http://", "https://")):
                        path = f"http://{host}:{port}{path}"
                    req_line = f"{method} {path} {version}\r\n".encode()
                    request_data = req_line + (proxy_auth.encode() if proxy_auth else b"") + headers
                destination_socket.sendall(request_data)
                client_socket.sendall(self.get_request_data(destination_socket))
        except Exception as e:
            logger.error(f"Request handling error: {e}")
        finally:
            client_socket.close()
            if destination_socket:
                destination_socket.close()

    def tunnel_data(self, client_socket: socket.socket, destination_socket: socket.socket) -> None:
        """Tunnel data between two sockets efficiently."""
        client_socket.setblocking(False)
        destination_socket.setblocking(False)

        sockets = [client_socket, destination_socket]

        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 30)

            if exceptional or not readable:
                logger.debug("Tunnel closed due to timeout or socket error.")
                break

            for src_socket in readable:
                try:
                    data = src_socket.recv(self.data_transfer_size)
                    if not data:
                        logger.debug("Tunnel closed gracefully.")
                        return

                    dst_socket = (
                        destination_socket if src_socket is client_socket else client_socket
                    )
                    dst_socket.sendall(data)

                except Exception as e:
                    logger.error(f"Tunnel error: {e}")
                    return

    def start(self) -> None:
        """Monitors the local proxy server for requests and sends them to get handled in a separate thread."""
        logger.info(f"Starting traffic proxy server on: {self.address}")
        if not self.running:
            self.running = True

        while self.running:
            try:
                client_socket, addr = self.server.accept()
            except socket.timeout:
                continue
            logger.debug(f"Got request from: {addr}")
            client_handler = threading.Thread(
                target=self.handle_client_request, args=(client_socket,)
            )
            client_handler.daemon = True
            client_handler.start()

    def start_daemon(self) -> None:
        """Starts the proxy server in its own thread to be non-blocking."""
        self.thread = threading.Thread(target=self.start, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stops the proxy server."""
        logger.info(f"Shutting down traffic proxy server on: {self.address}")
        self.running = False
        if self.thread and threading.current_thread() != self.thread:
            self.thread.join()
        self.server.close()


def main():
    url_patterns = ["ipify", "jagex", "cloudflare"]

    try:
        traffic_proxy_server = TrafficFilterProxy(
            port=8888,
            allowed_url_patterns=url_patterns,
        )
        traffic_proxy_server.start()
    except KeyboardInterrupt:
        sys.exit("Got keyboard interrupt, exiting.")


if __name__ == "__main__":
    main()
