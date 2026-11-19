import ipaddress
import os
import random
import struct
import tempfile
import unittest
from protocol import decode, display_filter, load_pcap, save_pcap, flow_text


def frame(
    proto=6,
    payload=b"",
    ipv6=False,
    src="192.0.2.1",
    dst="192.0.2.2",
    sport=12345,
    dport=8080,
    seq=1,
):
    # 构造指定网络层和传输层的报文，作为解析器的测试输入。
    transport = (
        struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18, 8192, 0, 0)
        + payload
        if proto == 6
        else struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        if proto == 17
        else payload
    )
    if ipv6:
        net = (
            struct.pack("!IHBB", 0x60000000, len(transport), proto, 64)
            + ipaddress.ip_address("2001:db8::1").packed
            + ipaddress.ip_address("2001:db8::2").packed
        )
    else:
        net = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(transport),
            1,
            0,
            64,
            proto,
            0,
            ipaddress.ip_address(src).packed,
            ipaddress.ip_address(dst).packed,
        )
    return (
        b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
        + struct.pack("!H", 0x86DD if ipv6 else 0x800)
        + net
        + transport
    )


class ProtocolTests(unittest.TestCase):
    def test_http_nonstandard_port(self):
        # 验证 HTTP 起始行识别不依赖标准端口。
        p = decode(0, frame(payload=b"GET /lab HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        self.assertEqual(p.protocol, "HTTP")
        self.assertEqual(p.dport, 8080)

    def test_port_does_not_imply_http(self):
        # 验证普通 TCP 数据不会仅因使用 80 端口而被识别为 HTTP。
        self.assertEqual(decode(0, frame(payload=b"hello", dport=80)).protocol, "TCP")

    def test_ipv6_udp(self):
        # 检查 IPv6 报文中的 UDP 标签是否正确。
        p = decode(0, frame(17, b"hello", True))
        self.assertTrue({"IPV6", "UDP"} <= p.tags)

    def test_icmp(self):
        # 检查 ICMP 报文的协议识别结果。
        self.assertEqual(decode(0, frame(1, b"\x08\0\0\0")).protocol, "ICMP")

    def test_dns(self):
        # 检查 53 端口上的 DNS 头部识别。
        p = decode(0, frame(17, struct.pack("!6H", 7, 0x100, 0, 0, 0, 0), dport=53))
        self.assertEqual(p.protocol, "DNS")

    def test_boolean_filter(self):
        # 检查协议过滤中的与、或、非运算。
        p = decode(0, frame())
        self.assertTrue(display_filter("(tcp or udp) and not ipv6")(p))
        self.assertFalse(display_filter("http")(p))

    def test_filter_code_rejected(self):
        # 验证过滤器拒绝函数调用、属性访问和未知协议名称。
        for expr in ['__import__("os")', "tcp.foo", "1", "nonsense"]:
            with self.assertRaises(ValueError):
                display_filter(expr)

    def test_pcap_roundtrip(self):
        # 核对 PCAP 保存和读取前后的原始字节及时间戳。
        p = decode(12.25, frame())
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        try:
            save_pcap(f.name, [p])
            q = list(load_pcap(f.name))[0]
            self.assertEqual(p.raw, q.raw)
            self.assertEqual(p.time, q.time)
        finally:
            os.unlink(f.name)

    def test_truncated_pcap(self):
        # 验证文件头截断时能够报告错误。
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b"bad")
        f.close()
        try:
            with self.assertRaises(ValueError):
                list(load_pcap(f.name))
        finally:
            os.unlink(f.name)

    def test_truncated_and_random_packets(self):
        # 使用逐字节截断和固定种子随机输入检查解析稳定性。
        raw = frame(payload=b"GET / HTTP/1.1\r\n")
        for n in range(len(raw)):
            self.assertIsNotNone(decode(0, raw[:n]))
        rng = random.Random(42)
        for _ in range(1000):
            size = rng.randrange(0, 300)
            data = b""
            if size:
                data = rng.getrandbits(size * 8).to_bytes(size, "little")
            decode(0, data)

    def test_fragment_not_parsed_as_tcp(self):
        # 验证 IPv4 分片不会直接进入 TCP 解析。
        b = bytearray(frame())
        b[20:22] = b"\x20\0"
        p = decode(0, bytes(b))
        self.assertNotIn("TCP", p.tags)

    def test_reverse_flow(self):
        # 检查通信方向反转后仍归入同一个 TCP 报文组。
        a = decode(0, frame())
        b = decode(1, frame(src="192.0.2.2", dst="192.0.2.1", sport=8080, dport=12345))
        self.assertEqual(a.flow(), b.flow())
        self.assertIn("双向", flow_text([a, b], a))

    def test_loopback(self):
        # 检查带 DLT_NULL 回环头的报文解析。
        b = struct.pack("<I", 2) + frame()[14:]
        self.assertEqual(decode(0, b, link=0).protocol, "TCP")

    def test_vlan(self):
        # 检查 VLAN 标签后的上层协议定位。
        b = frame()
        b = b[:12] + b"\x81\x00\x00\x07" + b[12:]
        self.assertEqual(decode(0, b).protocol, "TCP")

    def test_ipv4_declared_length_truncated(self):
        # 验证 IPv4 声明长度超过可用数据时停止上层识别。
        p = decode(0, frame(payload=b"GET / HTTP/1.1\r\n")[:-1])
        self.assertIn("MALFORMED", p.tags)
        self.assertNotIn("HTTP", p.tags)

    def test_ipv6_declared_length_truncated(self):
        # 验证 IPv6 负载截断时不会继续解析 UDP。
        p = decode(0, frame(17, b"hello", True)[:-1])
        self.assertIn("MALFORMED", p.tags)
        self.assertNotIn("UDP", p.tags)

    def test_udp_length_exceeds_ip_payload(self):
        # 验证 UDP 声明长度超出 IP 负载时报告异常。
        b = bytearray(frame(17, b"hello"))
        b[38:40] = struct.pack("!H", 500)
        self.assertIn("MALFORMED", decode(0, bytes(b)).tags)

    def test_filter_resource_limits(self):
        # 检查过滤表达式的长度和语法树规模限制。
        for expr in ["not " * 130 + "tcp", " or ".join(["tcp"] * 65)]:
            with self.assertRaises(ValueError):
                display_filter(expr)

    def test_filter_surrounding_whitespace(self):
        # 验证过滤表达式首尾空格不影响匹配结果。
        self.assertTrue(display_filter("  tcp  ")(decode(0, frame())))


if __name__ == "__main__":
    unittest.main(verbosity=2)
