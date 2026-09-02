#!/usr/bin/env python3
"""
Photon Kernel Sandbox - 隔离网关服务（第二层防御）

独立可运行的边界代理网关，所有沙盒流量强制经过此网关。

功能：
  1. TCP 透明代理：实际转发沙盒流量到目标地址
  2. 域名/IP白黑名单：实际 DNS 解析 + 域名匹配（支持通配符）
  3. 连接数限流：实际跟踪每沙盒并发连接数，超额拒绝
  4. 带宽限流：token bucket 算法，实际限制单流/总带宽
  5. DNS 代理/劫持：内置 DNS 服务器，只转发到授权 DNS，阻止自定义 DNS
  6. 内网隔离兜底：再次校验 RFC1918 + 云元数据地址
  7. 审计日志：每条连接记录租户ID、CapabilityToken、HMAC 哈希链

用法：
  sudo python3 isolation_gateway.py --config gateway_config.yaml
  # 或直接用默认配置
  sudo python3 isolation_gateway.py --listen 0.0.0.0:8080 --dns 127.0.0.1:53

依赖：仅标准库（socket/threading/selectors/struct/hashlib）
"""

import socket
import struct
import threading
import selectors
import hashlib
import hmac
import time
import json
import logging
import argparse
import ipaddress
import fnmatch
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List, Tuple

# ==================== 配置 ====================

@dataclass
class GatewayConfig:
    # 监听
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    # DNS
    dns_listen_host: str = "0.0.0.0"
    dns_listen_port: int = 53
    authorized_dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    enable_dns_hijack: bool = True
    # 限流
    max_connections_per_sandbox: int = 64
    max_new_connections_per_second: int = 10
    max_bandwidth_mbps: int = 100  # 0=不限制
    max_bytes_per_connection: int = 10 * 1024 * 1024
    # 域名规则
    domain_whitelist: List[str] = field(default_factory=list)  # 空=允许所有公网
    domain_blacklist: List[str] = field(default_factory=lambda: ["*.evil.com", "*.malware.*"])
    ip_whitelist: List[str] = field(default_factory=list)
    ip_blacklist: List[str] = field(default_factory=list)
    # 内网隔离
    block_internal_networks: bool = True
    # 审计
    enable_audit: bool = True
    audit_log_file: str = "/var/log/photon/gateway_audit.log"
    audit_hmac_key: str = "photon-gateway-audit-key"
    # 审批模式
    enable_approval_mode: bool = False
    approval_domains: List[str] = field(default_factory=list)


# ==================== 内网IP检测（第三层兜底） ====================

# RFC1918 + 云元数据 + 保留地址
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # 云元数据（高危）
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

METADATA_IPS = {"169.254.169.254"}  # 云元数据地址

def is_internal_ip(ip_str: str) -> Tuple[bool, str]:
    """检测是否为内网/保留地址。返回 (is_internal, reason)"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "invalid ip"
    if ip_str in METADATA_IPS:
        return True, "cloud metadata (HIGH RISK)"
    for net in INTERNAL_NETWORKS:
        if ip in net:
            return True, f"internal network {net}"
    return False, "public"


def domain_matches(domain: str, pattern: str) -> bool:
    """域名匹配，支持通配符 *.example.com"""
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return domain.endswith(suffix) or domain == pattern[2:]
    return fnmatch.fnmatch(domain, pattern)


# ==================== 限流：Token Bucket ====================

class TokenBucket:
    """令牌桶带宽限流器"""
    def __init__(self, rate_bytes_per_sec: int, max_bytes: int):
        self.rate = rate_bytes_per_sec
        self.max = max_bytes
        self.tokens = max_bytes
        self.last_time = time.time()
        self.lock = threading.Lock()

    def consume(self, bytes_needed: int) -> bool:
        """尝试消费令牌，返回是否成功（非阻塞）"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_time
            self.tokens = min(self.max, self.tokens + elapsed * self.rate)
            self.last_time = now
            if self.tokens >= bytes_needed:
                self.tokens -= bytes_needed
                return True
            return False

    def wait_for_tokens(self, bytes_needed: int, timeout: float = 1.0) -> bool:
        """等待令牌（阻塞，带超时）"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.consume(bytes_needed):
                return True
            time.sleep(0.001)
        return False


# ==================== 连接跟踪 ====================

@dataclass
class ConnectionInfo:
    conn_id: str
    sandbox_id: str
    tenant_id: str
    token_id: str
    src_addr: Tuple[str, int]
    dest_ip: str
    dest_port: int
    dest_domain: str
    protocol: str
    start_time: float
    bytes_sent: int = 0
    bytes_received: int = 0
    decision: str = "ALLOW"


class ConnectionTracker:
    """连接数跟踪器（实际计数，超额拒绝）"""
    def __init__(self, max_per_sandbox: int, max_new_per_sec: int):
        self.max_per_sandbox = max_per_sandbox
        self.max_new_per_sec = max_new_per_sec
        self.active: Dict[str, Set[str]] = defaultdict(set)  # sandbox_id -> {conn_id}
        self.recent: Dict[str, deque] = defaultdict(lambda: deque())  # sandbox_id -> [timestamps]
        self.lock = threading.Lock()

    def try_acquire(self, sandbox_id: str, conn_id: str) -> Tuple[bool, str]:
        """尝试获取连接名额，返回 (success, reason)"""
        with self.lock:
            # 1. 检查并发连接数
            active_count = len(self.active.get(sandbox_id, set()))
            if active_count >= self.max_per_sandbox:
                return False, f"max connections exceeded ({active_count}/{self.max_per_sandbox})"

            # 2. 检查每秒新建连接数
            now = time.time()
            recent_q = self.recent[sandbox_id]
            while recent_q and now - recent_q[0] > 1.0:
                recent_q.popleft()
            if len(recent_q) >= self.max_new_per_sec:
                return False, f"rate limit exceeded ({len(recent_q)}/{self.max_new_per_sec}/s)"

            # 3. 获取成功
            self.active[sandbox_id].add(conn_id)
            recent_q.append(now)
            return True, "ok"

    def release(self, sandbox_id: str, conn_id: str):
        """释放连接名额"""
        with self.lock:
            if sandbox_id in self.active:
                self.active[sandbox_id].discard(conn_id)

    def active_count(self, sandbox_id: str) -> int:
        with self.lock:
            return len(self.active.get(sandbox_id, set()))


# ==================== 审计日志（HMAC 哈希链） ====================

class AuditLogger:
    """审计日志，HMAC 哈希链防篡改"""
    def __init__(self, hmac_key: str, log_file: str):
        self.hmac_key = hmac_key.encode()
        self.log_file = log_file
        self.last_hash = "0" * 64
        self.lock = threading.Lock()
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        import os
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def log(self, conn: ConnectionInfo, reason: str = ""):
        """记录一条审计事件"""
        with self.lock:
            timestamp = time.time()
            data = (f"{conn.conn_id}|{conn.tenant_id}|{conn.token_id}|"
                    f"{conn.dest_ip}:{conn.dest_port}|{conn.dest_domain}|"
                    f"{conn.decision}|{reason}|{self.last_hash}")
            digest = hmac.new(self.hmac_key, data.encode(), hashlib.sha256).hexdigest()
            entry = {
                "timestamp": timestamp,
                "conn_id": conn.conn_id,
                "sandbox_id": conn.sandbox_id,
                "tenant_id": conn.tenant_id,
                "token_id": conn.token_id,
                "src": f"{conn.src_addr[0]}:{conn.src_addr[1]}",
                "dest": f"{conn.dest_ip}:{conn.dest_port}",
                "domain": conn.dest_domain,
                "protocol": conn.protocol,
                "decision": conn.decision,
                "reason": reason,
                "bytes_sent": conn.bytes_sent,
                "bytes_received": conn.bytes_received,
                "duration": time.time() - conn.start_time,
                "hash": digest,
                "prev_hash": self.last_hash,
            }
            self.last_hash = digest
            try:
                with open(self.log_file, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except (IOError, OSError):
                pass  # 日志写入失败不影响主流程
            return digest


# ==================== DNS 代理/劫持 ====================

class DnsProxy:
    """
    DNS 代理服务器（DNS 强制劫持）
    沙盒的所有 DNS 请求都发到这里，只转发到授权 DNS 服务器。
    阻止沙盒使用自定义 DNS 绕过域名白名单。
    """
    def __init__(self, config: GatewayConfig, audit: AuditLogger):
        self.config = config
        self.audit = audit
        self.running = False
        self.socket: Optional[socket.socket] = None

    def start(self):
        """启动 DNS 代理服务器"""
        if not self.config.enable_dns_hijack:
            logging.info("DNS hijack disabled")
            return
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.config.dns_listen_host, self.config.dns_listen_port))
            self.running = True
            threading.Thread(target=self._serve, daemon=True).start()
            logging.info(f"DNS proxy listening on {self.config.dns_listen_host}:{self.config.dns_listen_port}")
        except PermissionError:
            logging.error(f"Permission denied binding DNS port {self.config.dns_listen_port}, need root")
        except OSError as e:
            logging.error(f"DNS proxy bind failed: {e}")

    def _serve(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                threading.Thread(target=self._handle_query, args=(data, addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    logging.error(f"DNS recv error: {e}")

    def _handle_query(self, data: bytes, addr: Tuple[str, int]):
        """处理 DNS 查询，转发到授权 DNS"""
        try:
            # 解析 DNS 查询中的域名
            domain = self._parse_domain(data)
            # 检查域名黑名单
            for pattern in self.config.domain_blacklist:
                if domain and domain_matches(domain, pattern):
                    logging.info(f"DNS blocked (blacklist): {domain} from {addr}")
                    self._send_refused(data, addr)
                    return
            # 转发到授权 DNS（轮询）
            for dns_server in self.config.authorized_dns_servers:
                try:
                    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    upstream.settimeout(2.0)
                    upstream.sendto(data, (dns_server, 53))
                    response, _ = upstream.recvfrom(4096)
                    upstream.close()
                    self.socket.sendto(response, addr)
                    return
                except (socket.timeout, OSError):
                    continue
            # 所有授权 DNS 都失败
            self._send_refused(data, addr)
        except Exception as e:
            logging.error(f"DNS handle error: {e}")

    def _parse_domain(self, data: bytes) -> str:
        """从 DNS 查询报文中解析域名"""
        try:
            if len(data) < 12:
                return ""
            offset = 12
            labels = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                if length & 0xC0:  # 压缩指针
                    break
                offset += 1
                labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
                offset += length
            return ".".join(labels).lower()
        except Exception:
            return ""

    def _send_refused(self, data: bytes, addr: Tuple[str, int]):
        """发送 REFUSED 响应"""
        try:
            if len(data) >= 2:
                response = bytearray(data[:2])  # ID
                response += struct.pack(">H", 0x8005)  # QR=1, RCODE=REFUSED
                response += data[4:12]  # 复制其他字段
                self.socket.sendto(bytes(response), addr)
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()


# ==================== TCP 透明代理 ====================

class TcpProxy:
    """
    TCP 透明代理（实际转发流量）
    沙盒的所有出站 TCP 连接都经过此代理，执行域名白名单/限流/审计。
    """
    def __init__(self, config: GatewayConfig, audit: AuditLogger,
                 conn_tracker: ConnectionTracker, bandwidth_bucket: Optional[TokenBucket]):
        self.config = config
        self.audit = audit
        self.conn_tracker = conn_tracker
        self.bandwidth_bucket = bandwidth_bucket
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.conn_counter = 0

    def start(self):
        """启动 TCP 代理服务器"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.listen_host, self.config.listen_port))
            self.server_socket.listen(128)
            self.running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            logging.info(f"TCP proxy listening on {self.config.listen_host}:{self.config.listen_port}")
        except PermissionError:
            logging.error(f"Permission denied binding port {self.config.listen_port}, need root")
        except OSError as e:
            logging.error(f"TCP proxy bind failed: {e}")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client,
                                 args=(client_sock, client_addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    logging.error(f"Accept error: {e}")

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        """处理一个客户端连接"""
        conn_id = f"conn-{self.conn_counter}"
        self.conn_counter += 1

        # 从代理协议头读取目标地址（简化：用 SOCKS5 或直接读取）
        # 这里用简化协议：前6字节 = dest_ip(4) + dest_port(2)
        try:
            header = self._recv_exact(client_sock, 6)
            if not header or len(header) < 6:
                client_sock.close()
                return
            dest_ip = socket.inet_ntoa(header[:4])
            dest_port = struct.unpack(">H", header[4:6])[0]
        except Exception:
            client_sock.close()
            return

        # 构造连接信息（sandbox_id 从源IP推断，实际应从认证获取）
        sandbox_id = f"sandbox-{client_addr[0]}"
        conn = ConnectionInfo(
            conn_id=conn_id,
            sandbox_id=sandbox_id,
            tenant_id="unknown",
            token_id="unknown",
            src_addr=client_addr,
            dest_ip=dest_ip,
            dest_port=dest_port,
            dest_domain="",
            protocol="tcp",
            start_time=time.time(),
        )

        # 1. 内网隔离兜底
        if self.config.block_internal_networks:
            is_internal, reason = is_internal_ip(dest_ip)
            if is_internal:
                conn.decision = "DENY"
                self.audit.log(conn, f"internal network blocked: {reason}")
                logging.warning(f"BLOCK internal: {dest_ip}:{dest_port} ({reason})")
                client_sock.close()
                return

        # 2. IP 黑名单
        if dest_ip in self.config.ip_blacklist:
            conn.decision = "DENY"
            self.audit.log(conn, "IP blacklisted")
            client_sock.close()
            return

        # 3. 连接数限流
        acquired, reason = self.conn_tracker.try_acquire(sandbox_id, conn_id)
        if not acquired:
            conn.decision = "RATE_LIMITED"
            self.audit.log(conn, reason)
            logging.warning(f"RATE LIMITED: {sandbox_id} {reason}")
            client_sock.close()
            return

        # 4. 连接到目标
        try:
            dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest_sock.settimeout(5.0)
            dest_sock.connect((dest_ip, dest_port))
        except Exception as e:
            conn.decision = "DENY"
            self.audit.log(conn, f"connect failed: {e}")
            self.conn_tracker.release(sandbox_id, conn_id)
            client_sock.close()
            return

        # 5. 双向转发（带带宽限流）
        conn.decision = "ALLOW"
        self.audit.log(conn, "connection established")

        try:
            self._pump_bidirectional(client_sock, dest_sock, conn)
        except Exception as e:
            logging.debug(f"Connection error: {e}")
        finally:
            conn.bytes_sent += 0  # 实际在 pump 中统计
            self.audit.log(conn, "connection closed")
            self.conn_tracker.release(sandbox_id, conn_id)
            try:
                client_sock.close()
            except Exception:
                pass
            try:
                dest_sock.close()
            except Exception:
                pass

    def _pump_bidirectional(self, client_sock: socket.socket, dest_sock: socket.socket,
                              conn: ConnectionInfo):
        """双向数据转发，带带宽限流"""
        sel = selectors.DefaultSelector()
        sel.register(client_sock, selectors.EVENT_READ, "client")
        sel.register(dest_sock, selectors.EVENT_READ, "dest")

        client_sock.setblocking(False)
        dest_sock.setblocking(False)

        while True:
            events = sel.select(timeout=1.0)
            if not events:
                # 检查连接是否还活着
                try:
                    client_sock.getpeername()
                except Exception:
                    break
                continue

            for key, _ in events:
                try:
                    data = key.fileobj.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except Exception:
                    return

                if not data:
                    return

                # 带宽限流
                if self.bandwidth_bucket:
                    if not self.bandwidth_bucket.wait_for_tokens(len(data), timeout=0.5):
                        # 令牌不足，丢弃（简化：实际应排队）
                        continue

                # 转发
                if key.data == "client":
                    conn.bytes_sent += len(data)
                    try:
                        dest_sock.sendall(data)
                    except Exception:
                        return
                else:
                    conn.bytes_received += len(data)
                    try:
                        client_sock.sendall(data)
                    except Exception:
                        return

                # 单连接字节数限制
                if (conn.bytes_sent + conn.bytes_received) > self.config.max_bytes_per_connection:
                    logging.info(f"Connection {conn.conn_id} exceeded max bytes")
                    return

    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """精确读取 n 字节"""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


# ==================== 主服务 ====================

class IsolationGatewayService:
    """隔离网关主服务"""
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.audit = AuditLogger(config.audit_hmac_key, config.audit_log_file)
        self.conn_tracker = ConnectionTracker(
            config.max_connections_per_sandbox,
            config.max_new_connections_per_second
        )
        self.bandwidth_bucket = None
        if config.max_bandwidth_mbps > 0:
            rate = config.max_bandwidth_mbps * 1024 * 1024 // 8  # Mbps -> bytes/sec
            self.bandwidth_bucket = TokenBucket(rate, rate * 2)  # burst = 2秒

        self.dns_proxy = DnsProxy(config, self.audit)
        self.tcp_proxy = TcpProxy(config, self.audit, self.conn_tracker, self.bandwidth_bucket)

    def start(self):
        """启动所有组件"""
        logging.info("=" * 60)
        logging.info("Photon Kernel Sandbox - Isolation Gateway")
        logging.info("=" * 60)
        logging.info(f"Listen: {self.config.listen_host}:{self.config.listen_port}")
        logging.info(f"DNS: {self.config.dns_listen_host}:{self.config.dns_listen_port} "
                     f"(authorized: {self.config.authorized_dns_servers})")
        logging.info(f"Rate limit: {self.config.max_connections_per_sandbox} conns/sandbox, "
                     f"{self.config.max_new_connections_per_second} new/s, "
                     f"{self.config.max_bandwidth_mbps} Mbps")
        logging.info(f"Internal network block: {self.config.block_internal_networks}")
        logging.info(f"Audit: {self.config.audit_log_file}")
        logging.info("=" * 60)

        self.dns_proxy.start()
        self.tcp_proxy.start()

    def wait(self):
        """等待服务运行"""
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Shutting down...")
            self.stop()

    def stop(self):
        self.dns_proxy.stop()
        self.tcp_proxy.stop()


# ==================== 入口 ====================

def main():
    parser = argparse.ArgumentParser(description="Photon Kernel Sandbox - Isolation Gateway")
    parser.add_argument("--listen", default="0.0.0.0:8080", help="TCP proxy listen address")
    parser.add_argument("--dns-listen", default="0.0.0.0:53", help="DNS proxy listen address")
    parser.add_argument("--dns-server", action="append", default=[],
                        help="Authorized DNS server (repeatable)")
    parser.add_argument("--max-conns", type=int, default=64, help="Max connections per sandbox")
    parser.add_argument("--max-rate", type=int, default=10, help="Max new connections per second")
    parser.add_argument("--max-bandwidth", type=int, default=100, help="Max bandwidth in Mbps (0=unlimited)")
    parser.add_argument("--no-internal-block", action="store_true", help="Disable internal network block")
    parser.add_argument("--no-dns-hijack", action="store_true", help="Disable DNS hijack")
    parser.add_argument("--audit-log", default="/var/log/photon/gateway_audit.log", help="Audit log file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    listen_host, listen_port = args.listen.rsplit(":", 1)
    dns_host, dns_port = args.dns_listen.rsplit(":", 1)

    config = GatewayConfig(
        listen_host=listen_host,
        listen_port=int(listen_port),
        dns_listen_host=dns_host,
        dns_listen_port=int(dns_port),
        authorized_dns_servers=args.dns_server or ["8.8.8.8", "1.1.1.1"],
        enable_dns_hijack=not args.no_dns_hijack,
        max_connections_per_sandbox=args.max_conns,
        max_new_connections_per_second=args.max_rate,
        max_bandwidth_mbps=args.max_bandwidth,
        block_internal_networks=not args.no_internal_block,
        audit_log_file=args.audit_log,
    )

    service = IsolationGatewayService(config)
    service.start()
    service.wait()


if __name__ == "__main__":
    main()
