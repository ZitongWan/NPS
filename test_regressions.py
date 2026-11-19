import collections
import queue
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app import App
from local_validation import validate
from protocol import decode, flow_text, load_pcap, save_pcap
from test_protocol import frame


class PcapProtectionTests(unittest.TestCase):
    def test_invalid_record_preserves_existing_file(self):
        # 非法记录保存失败后，原文件内容保持完整且没有遗留临时文件。
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(b"existing capture")
            for timestamp, wirelen in (
                (-1, 54),
                (float("nan"), 54),
                (2**32, 54),
                (1, 1),
            ):
                with self.subTest(timestamp=timestamp, wirelen=wirelen):
                    packet = decode(timestamp, frame(), wirelen=wirelen)
                    with self.assertRaises(ValueError):
                        save_pcap(path, [packet])
                    self.assertEqual(path.read_bytes(), b"existing capture")
                    self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_replace_failure_preserves_existing_file(self):
        # 模拟目标文件被占用，确认替换失败不会损坏已有数据。
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(b"existing capture")
            with patch("protocol.os.replace", side_effect=PermissionError("busy")):
                with self.assertRaises(PermissionError):
                    save_pcap(path, [decode(1, frame())])
            self.assertEqual(path.read_bytes(), b"existing capture")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_microsecond_rounding_carries_to_next_second(self):
        # 小数秒舍入到一百万微秒时，应正确进位到下一秒。
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            save_pcap(path, [decode(12.9999996, frame())])
            self.assertEqual(list(load_pcap(path))[0].time, 13.0)

    def test_pcap_byte_orders_and_timestamp_units(self):
        # 同一报文在大小端及微秒、纳秒文件中应得到一致的时间和字节。
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            raw = frame()
            for order in ("<", ">"):
                for magic, scale in ((0xA1B2C3D4, 1000000), (0xA1B23C4D, 1000000000)):
                    with self.subTest(order=order, scale=scale):
                        header = struct.pack(
                            order + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1
                        )
                        record = struct.pack(
                            order + "IIII", 12, scale // 4, len(raw), len(raw)
                        )
                        path.write_bytes(header + record + raw)
                        packet = list(load_pcap(path))[0]
                        self.assertEqual(packet.time, 12.25)
                        self.assertEqual(packet.raw, raw)

    def test_invalid_global_header_is_rejected(self):
        # 即使文件没有报文，也应拒绝零捕获长度和不支持的链路类型。
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            for snap, link in ((0, 1), (65535, 999)):
                with self.subTest(snap=snap, link=link):
                    path.write_bytes(
                        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snap, link)
                    )
                    with self.assertRaises(ValueError):
                        list(load_pcap(path))


class FlowPresentationTests(unittest.TestCase):
    def test_flow_includes_ack_flags_time_and_ipv6_endpoints(self):
        # 检查 ACK 字段、相对时间及 IPv6 地址在流窗口中的完整显示。
        raw = bytearray(frame(ipv6=True))
        raw[62:66] = struct.pack("!I", 1234)
        first = decode(10, bytes(raw))
        second = decode(10.025, bytes(raw))
        output = flow_text([first, second], first)
        self.assertEqual(first.ack, 1234)
        self.assertIn("ack=1234", output)
        self.assertIn("PSH|ACK (0x18)", output)
        self.assertIn("+25.000 ms", output)
        self.assertIn("[2001:db8::1]:12345 -> [2001:db8::2]:8080", output)

    def test_flow_marks_payload_preview_limit(self):
        # 超过预览长度的负载应有数量提示，原始负载仍保留在报文对象中。
        packet = decode(10, frame(payload=b"x" * 5000))
        output = flow_text([packet], packet)
        self.assertIn("负载显示：4096 / 5000 字节", output)
        self.assertEqual(len(packet.payload), 5000)


class GuiStateTests(unittest.TestCase):
    def setUp(self):
        # 使用控件替身检查状态转换，不启动窗口或访问真实网络接口。
        self.view = App.__new__(App)
        self.old_packets = [decode(1, frame())]
        self.view.packets = self.old_packets
        self.view.counts = collections.Counter({"TCP": 1})
        self.view.q = queue.Queue()
        self.view.dropped = 0
        self.view.active = Mock(return_value=False)
        self.view.expr = Mock()
        self.view.expr.get.return_value = "tcp"
        self.view.search = Mock()
        self.view.search.get.return_value = ""
        self.view.applied_search = ""
        self.view.predicate = lambda packet: True
        self.view.table = Mock()
        self.view.table.get_children.return_value = ["0"]
        self.view.detail = Mock()
        self.view.hex = Mock()

    def test_invalid_filter_does_not_replace_imported_state(self):
        # 导入前发现过滤表达式错误时，应保留旧报文、列表和详情。
        self.view.expr.get.return_value = "tcp and"
        with patch("app.filedialog.askopenfilename", return_value="unused.pcap"), patch(
            "app.messagebox.showerror"
        ) as error:
            self.view.open()
        self.assertIs(self.view.packets, self.old_packets)
        self.view.table.delete.assert_not_called()
        self.view.detail.delete.assert_not_called()
        error.assert_called_once()

    def test_corrupt_import_preserves_existing_packets(self):
        # 文件读取失败时，不清除已保存的报文或协议统计。
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"bad")
            with patch("app.filedialog.askopenfilename", return_value=str(path)), patch(
                "app.messagebox.showerror"
            ):
                self.view.open()
        self.assertEqual(len(self.view.packets), 1)
        self.assertEqual(self.view.counts, {"TCP": 1})
        self.view.table.delete.assert_not_called()

    def test_filter_rebuild_clears_stale_details(self):
        # 报文被筛选隐藏后，旧的协议字段和原始字节应同时清空。
        self.view.expr.get.return_value = "http"
        self.assertTrue(self.view.apply_filter())
        self.view.table.insert.assert_not_called()
        self.view.detail.delete.assert_called_once_with("1.0", "end")
        self.view.hex.delete.assert_called_once_with("1.0", "end")

    def test_import_and_clear_update_protocol_counts(self):
        # 导入重新建立协议计数，清空后所有计数回到零。
        packet = decode(2, frame(payload=b"GET / HTTP/1.1\r\n"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "http.pcap"
            save_pcap(path, [packet])
            with patch("app.filedialog.askopenfilename", return_value=str(path)):
                self.view.open()
        self.assertEqual(self.view.counts, {"HTTP": 1})
        self.view.clear()
        self.assertEqual(self.view.counts, {})
        self.assertEqual(self.view.packets, [])


class ValidationOutputTests(unittest.TestCase):
    def test_reference_samples_are_protected(self):
        # 复测脚本拒绝将报告样例目录作为输出位置。
        reference = Path(__file__).parent / "samples"
        with patch("local_validation.Npcap") as driver:
            with self.assertRaisesRegex(ValueError, "samples"):
                validate(reference)
            driver.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
