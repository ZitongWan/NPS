"""Bounded packet decoding, safe display filters, classic PCAP I/O."""
import ast
import datetime
import ipaddress
import math
import os
import re
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Packet:
    time: float
    raw: bytes
    wirelen: int
    link: int
    src: str = ""
    dst: str = ""
    protocol: str = "OTHER"
    info: str = ""
    tags: set = field(default_factory=set)
    details: list = field(default_factory=list)
    sport: int = 0
    dport: int = 0
    seq: int = 0
    flags: int = 0
    payload: bytes = b""
    ack: int = 0

    def flow(self):
        # 对两端地址和端口排序，使双向 TCP 报文使用相同的分组键。
        return (
            tuple(sorted(((self.src, self.sport), (self.dst, self.dport))))
            if "TCP" in self.tags
            else None
        )


def decode(ts, raw, wirelen=None, link=1):
    # 根据链路类型逐层解析报文，将字段和异常信息保存到 Packet。
    p = Packet(ts, raw, len(raw) if wirelen is None else wirelen, link)

    def need(b, n):
        # 读取字段前检查剩余字节数，防止截断数据导致越界解析。
        if len(b) < n:
            raise ValueError(f"截断：需要 {n} 字节，实际 {len(b)}")

    try:
        b = raw
        if link == 1:
            need(b, 14)
            mac = lambda x: ":".join(f"{c:02x}" for c in x)
            p.details.append(f"Ethernet {mac(b[6:12])} -> {mac(b[:6])}")
            kind = struct.unpack("!H", b[12:14])[0]
            b = b[14:]
            for _ in range(4):
                if kind not in (0x8100, 0x88A8):
                    break
                need(b, 4)
                tci, kind = struct.unpack("!HH", b[:4])
                b = b[4:]
                p.details.append(f"VLAN id={tci & 4095}")
        elif link in (0, 108):
            need(b, 4)
            family = int.from_bytes(b[:4], "little" if link == 0 else "big")
            b = b[4:]
            kind = 0x800 if family == 2 else 0x86DD if family in (10, 24, 28, 30) else 0
        elif link in (12, 101):
            need(b, 1)
            kind = {4: 0x800, 6: 0x86DD}.get(b[0] >> 4, 0)
        else:
            raise ValueError(f"不支持链路类型 {link}")
        if kind == 0x806:
            need(b, 8)
            hw, proto, hlen, plen, op = struct.unpack("!HHBBH", b[:8])
            need(b, 8 + 2 * (hlen + plen))
            p.protocol = "ARP"
            p.tags.add("ARP")
            if plen == 4 and proto == 0x800:
                p.src = str(ipaddress.ip_address(b[8 + hlen : 8 + hlen + 4]))
                p.dst = str(
                    ipaddress.ip_address(
                        b[8 + 2 * hlen + plen : 8 + 2 * hlen + plen + 4]
                    )
                )
            p.info = f"operation={op}"
            p.details.append(p.info)
            return p
        if kind == 0x800:
            need(b, 20)
            ihl = (b[0] & 15) * 4
            total = int.from_bytes(b[2:4], "big")
            if b[0] >> 4 != 4 or ihl < 20 or total < ihl:
                raise ValueError("非法 IPv4 头部")
            need(b, ihl)
            p.tags.add("IPV4")
            p.protocol = "IPv4"
            p.src = str(ipaddress.ip_address(b[12:16]))
            p.dst = str(ipaddress.ip_address(b[16:20]))
            frag = int.from_bytes(b[6:8], "big")
            proto = b[9]
            p.details.append(
                f"IPv4 ihl={ihl} length={total} TTL={b[8]} protocol={proto} fragment_offset={frag & 8191}"
            )
            need(b, total)
            b = b[ihl:total]
            if frag & 0x3FFF:
                p.info = "IPv4 分片：未重组，不解析上层"
                return p
        elif kind == 0x86DD:
            need(b, 40)
            if b[0] >> 4 != 6:
                raise ValueError("非法 IPv6 版本")
            p.tags.add("IPV6")
            p.protocol = "IPv6"
            p.src = str(ipaddress.ip_address(b[8:24]))
            p.dst = str(ipaddress.ip_address(b[24:40]))
            size = int.from_bytes(b[4:6], "big")
            proto = b[6]
            p.details.append(f"IPv6 payload_length={size} hop_limit={b[7]}")
            need(b, 40 + size)
            b = b[40 : 40 + size]
            for _ in range(8):
                if proto not in (0, 43, 44, 60, 51):
                    break
                need(b, 8)
                old = proto
                proto = b[0]
                n = 8 if old == 44 else (b[1] + 2) * 4 if old == 51 else (b[1] + 1) * 8
                need(b, n)
                p.details.append(f"IPv6 extension={old} size={n}")
                if old == 44:
                    p.info = "IPv6 分片：未重组，不解析上层"
                    return p
                b = b[n:]
        else:
            p.info = f"EtherType=0x{kind:04x}"
            return p
        if proto == 6:
            need(b, 20)
            p.sport, p.dport, p.seq, ack = struct.unpack("!HHII", b[:12])
            p.ack = ack
            n = (b[12] >> 4) * 4
            if n < 20:
                raise ValueError("非法 TCP data offset")
            need(b, n)
            p.flags = b[13]
            p.tags.add("TCP")
            p.protocol = "TCP"
            p.payload = b[n:]
            p.info = f"{p.sport} -> {p.dport} seq={p.seq} ack={ack} flags=0x{p.flags:02x} payload={len(p.payload)}"
            p.details.append("TCP " + p.info)
            if re.match(
                rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/1\.[01]\r\n|^HTTP/1\.[01] [0-9]{3} ",
                p.payload,
            ):
                p.protocol = "HTTP"
                p.tags.add("HTTP")
                p.info = p.payload.split(b"\r\n")[0].decode("ascii", "replace")
                p.details.append("HTTP/1 起始行 " + p.info)
            elif (
                len(p.payload) >= 5
                and p.payload[0] in (20, 21, 22, 23)
                and p.payload[1] == 3
                and p.payload[2] <= 4
            ):
                p.protocol = "TLS?"
                p.tags.add("TLS")
                p.details.append("TLS 记录头（特征匹配）")
        elif proto == 17:
            need(b, 8)
            p.sport, p.dport, n, _ = struct.unpack("!HHHH", b[:8])
            if n < 8:
                raise ValueError("非法 UDP length")
            need(b, n)
            p.tags.add("UDP")
            p.protocol = "UDP"
            p.payload = b[8:n]
            p.info = f"{p.sport} -> {p.dport} length={n}"
            p.details.append("UDP " + p.info)
            if 53 in (p.sport, p.dport) and len(p.payload) >= 12:
                ident, flags, qd, an, ns, ar = struct.unpack("!6H", p.payload[:12])
                if (flags >> 11) & 15 == 0:
                    p.tags.add("DNS")
                    p.protocol = "DNS"
                    p.info = f"id={ident} QR={flags >> 15} questions={qd} answers={an}"
                    p.details.append("DNS 头部 " + p.info)
        elif proto in (1, 58):
            need(b, 4)
            p.protocol = "ICMP" if proto == 1 else "ICMPv6"
            p.tags.add(p.protocol.upper())
            p.info = f"type={b[0]} code={b[1]}"
            p.details.append(p.protocol + " " + p.info)
        else:
            p.info = f"IP protocol/next header={proto}"
    except (ValueError, struct.error, IndexError) as e:
        p.tags.add("MALFORMED")
        p.info = str(e)
        p.details.append("解析提示：" + str(e))
    return p


def display_filter(expression):
    # 检查过滤表达式的语法树，只接受协议名称和布尔运算。
    expression = expression.strip()
    if not expression.strip():
        return lambda p: True
    if len(expression) > 512:
        raise ValueError("过滤表达式不能超过 512 个字符")
    tree = ast.parse(expression, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 128:
        raise ValueError("过滤表达式过于复杂")
    allowed = {
        "TCP",
        "UDP",
        "HTTP",
        "IPV4",
        "IPV6",
        "ICMP",
        "ICMPV6",
        "ARP",
        "DNS",
        "TLS",
        "MALFORMED",
        "OTHER",
    }
    for node in ast.walk(tree):
        if not isinstance(
            node,
            (
                ast.Expression,
                ast.BoolOp,
                ast.UnaryOp,
                ast.Name,
                ast.Load,
                ast.And,
                ast.Or,
                ast.Not,
            ),
        ):
            raise ValueError("仅支持协议名和 and / or / not / 括号")
        if isinstance(node, ast.Name) and node.id.upper() not in allowed:
            raise ValueError("未知协议：" + node.id)

    def evaluate(n, p):
        # 递归计算协议标签的布尔组合，判断报文是否匹配。
        if isinstance(n, ast.Name):
            return n.id.upper() in p.tags or n.id.upper() == p.protocol.upper()
        if isinstance(n, ast.UnaryOp):
            return not evaluate(n.operand, p)
        if isinstance(n, ast.BoolOp):
            return (all if isinstance(n.op, ast.And) else any)(
                evaluate(v, p) for v in n.values
            )
        return evaluate(n.body, p)

    return lambda p: evaluate(tree, p)


def save_pcap(path, packets):
    # 先写入同目录临时文件，全部成功后替换目标，保留保存失败前的文件。
    path = Path(path)
    packets = list(packets)
    links = {p.link for p in packets}
    if len(links) > 1:
        raise ValueError("PCAP 不能混合不同链路类型")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as f:
            temporary = Path(f.name)
            f.write(
                struct.pack(
                    "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, next(iter(links), 1)
                )
            )
            for p in packets:
                if not math.isfinite(p.time) or p.time < 0:
                    raise ValueError("非法 PCAP 时间戳")
                sec = int(p.time)
                carry, us = divmod(round((p.time - sec) * 1e6), 1000000)
                sec += carry
                if (
                    sec > 0xFFFFFFFF
                    or not len(p.raw) <= p.wirelen <= 0xFFFFFFFF
                    or len(p.raw) > 65535
                ):
                    raise ValueError("PCAP 记录长度或时间戳超出范围")
                f.write(struct.pack("<IIII", sec, us, len(p.raw), p.wirelen))
                f.write(p.raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def load_pcap(path, limit=5000):
    # 逐条读取 PCAP 记录，校验长度和时间戳后解析报文。
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) != 24:
            raise ValueError("PCAP 文件头截断")
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1e6),
            b"\xa1\xb2\xc3\xd4": (">", 1e6),
            b"\x4d\x3c\xb2\xa1": ("<", 1e9),
            b"\xa1\xb2\x3c\x4d": (">", 1e9),
        }
        if head[:4] not in formats:
            raise ValueError("仅支持经典 PCAP，请将 PCAPNG 另存为 PCAP")
        order, scale = formats[head[:4]]
        major, minor, _, _, snap, link = struct.unpack(order + "HHIIII", head[4:])
        if (major, minor) != (2, 4):
            raise ValueError("不支持的 PCAP 版本")
        if snap == 0:
            raise ValueError("PCAP 最大捕获长度必须大于 0")
        if link not in (0, 1, 12, 108, 101):
            raise ValueError(f"不支持的 PCAP 链路类型 {link}")
        for i in range(limit + 1):
            h = f.read(16)
            if not h:
                return
            if i == limit:
                raise ValueError(f"文件超过 {limit} 包限制，请先分割文件")
            if len(h) != 16:
                raise ValueError("记录头截断")
            sec, frac, cap, wire = struct.unpack(order + "IIII", h)
            if cap > 65535 or cap > snap or cap > wire or frac >= scale:
                raise ValueError("非法 PCAP 记录长度或时间戳")
            raw = f.read(cap)
            if len(raw) != cap:
                raise ValueError("记录数据截断")
            yield decode(sec + frac / scale, raw, wire, link)


def flow_text(packets, selected):
    # 筛选与选中报文端点相同的双向数据，按捕获顺序组织显示内容。
    flow = selected.flow()
    if flow is None:
        return "请选择一个 TCP / HTTP 报文。"

    def endpoint(value):
        # 用方括号包围 IPv6 地址，区分地址中的冒号与端口分隔符。
        address, port = value
        return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

    lines = [
        "TCP 双向流",
        f"连接：{endpoint(flow[0])} <-> {endpoint(flow[1])}",
        "报文按捕获顺序排列。",
        "",
    ]
    first_time = None
    for p in packets:
        if p.flow() == flow:
            if first_time is None:
                first_time = p.time
            stamp = datetime.datetime.fromtimestamp(p.time).strftime("%H:%M:%S.%f")
            elapsed = (p.time - first_time) * 1000
            flags = (
                "|".join(
                    label
                    for mask, label in (
                        (0x01, "FIN"),
                        (0x02, "SYN"),
                        (0x04, "RST"),
                        (0x08, "PSH"),
                        (0x10, "ACK"),
                        (0x20, "URG"),
                        (0x40, "ECE"),
                        (0x80, "CWR"),
                    )
                    if p.flags & mask
                )
                or "无"
            )
            lines.append(
                f"{stamp} (+{elapsed:.3f} ms) "
                f"{endpoint((p.src, p.sport))} -> {endpoint((p.dst, p.dport))} "
                f"seq={p.seq} ack={p.ack} flags={flags} (0x{p.flags:02x}) bytes={len(p.payload)}"
            )
            if p.payload:
                lines.append(p.payload[:4096].decode("utf-8", "replace"))
                if len(p.payload) > 4096:
                    lines.append(f"负载显示：4096 / {len(p.payload)} 字节")
    return "\n".join(lines)
