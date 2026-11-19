"""Capture only this script's loopback HTTP traffic. No external network requests."""
import http.server
import threading
import urllib.request
import time
import json
from pathlib import Path
from capture import Npcap
from protocol import decode, save_pcap


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        # 返回固定长度的 HTTP 正文，供本地抓包测试核对。
        body = b"Yanqi EX1A local validation\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        # 关闭 HTTP 服务的默认日志，使终端集中显示验证结果。
        pass


def validate():
    # 在回环接口捕获三次 HTTP 请求，并保存 PCAP 和验证结果。
    n = Npcap()
    interfaces = n.interfaces()
    loop = next(
        (x for x in interfaces if "loopback" in (x[0] + " " + x[1]).lower()), None
    )
    if not loop:
        raise RuntimeError("Npcap 回环接口不存在")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stop = threading.Event()
    ready = threading.Event()
    packets = []
    errors = []

    def worker():
        # 启动受控采集，并通过事件通知主线程采集已就绪或失败。
        try:
            n.run(
                loop[0],
                f"tcp port {port} and host 127.0.0.1",
                stop,
                lambda *args: packets.append(decode(*args)),
                ready.set,
            )
        except Exception as e:
            errors.append(str(e))
            ready.set()

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        if not ready.wait(5) or errors:
            raise RuntimeError(str(errors))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for i in range(3):
            with opener.open(
                f"http://127.0.0.1:{port}/experiment/{i}", timeout=5
            ) as response:
                assert response.read() == b"Yanqi EX1A local validation\n"
        time.sleep(0.4)
    finally:
        stop.set()
        thread.join(5)
        server.shutdown()
        server.server_close()
    assert not thread.is_alive() and not errors
    assert any(p.protocol == "HTTP" and p.info.startswith("GET") for p in packets)
    assert any(p.protocol == "HTTP" and p.info.startswith("HTTP/") for p in packets)
    assert all(
        p.src == "127.0.0.1" and p.dst == "127.0.0.1" and port in (p.sport, p.dport)
        for p in packets
    )
    samples = Path(__file__).parent / "samples"
    samples.mkdir(exist_ok=True)
    save_pcap(samples / "local_http.pcap", packets)
    result = {
        "capture": "PASS",
        "interface": loop[0],
        "port": port,
        "packets": len(packets),
        "http_packets": sum(p.protocol == "HTTP" for p in packets),
        "stop": "PASS",
        "BPF_scope": "PASS",
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    (samples / "validation.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    validate()
