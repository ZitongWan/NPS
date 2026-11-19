"""Windows Npcap bindings. Only captures the explicitly selected interface."""
import ctypes as C
import os
import time


class Interface(C.Structure):
    pass


Interface._fields_ = [
    ("next", C.POINTER(Interface)),
    ("name", C.c_char_p),
    ("description", C.c_char_p),
    ("addresses", C.c_void_p),
    ("flags", C.c_uint),
]


class Header(C.Structure):
    _fields_ = [
        ("sec", C.c_long),
        ("usec", C.c_long),
        ("caplen", C.c_uint32),
        ("length", C.c_uint32),
    ]


class Program(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


class Npcap:
    def __init__(self):
        # 加载 Npcap 动态库，并声明接口参数及返回值的 C 类型。
        folder = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"
        )
        self.directory = os.add_dll_directory(folder)
        self.lib = C.CDLL(os.path.join(folder, "wpcap.dll"))
        signatures = {
            "pcap_findalldevs": (
                [C.POINTER(C.POINTER(Interface)), C.c_char_p],
                C.c_int,
            ),
            "pcap_freealldevs": ([C.POINTER(Interface)], None),
            "pcap_open_live": (
                [C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p],
                C.c_void_p,
            ),
            "pcap_compile": (
                [C.c_void_p, C.POINTER(Program), C.c_char_p, C.c_int, C.c_uint32],
                C.c_int,
            ),
            "pcap_setfilter": ([C.c_void_p, C.POINTER(Program)], C.c_int),
            "pcap_freecode": ([C.POINTER(Program)], None),
            "pcap_setnonblock": ([C.c_void_p, C.c_int, C.c_char_p], C.c_int),
            "pcap_datalink": ([C.c_void_p], C.c_int),
            "pcap_next_ex": (
                [
                    C.c_void_p,
                    C.POINTER(C.POINTER(Header)),
                    C.POINTER(C.POINTER(C.c_ubyte)),
                ],
                C.c_int,
            ),
            "pcap_geterr": ([C.c_void_p], C.c_char_p),
            "pcap_close": ([C.c_void_p], None),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.lib, name)
            fn.argtypes = args
            fn.restype = result

    def interfaces(self):
        # 复制网卡名称和描述后释放 Npcap 分配的接口链表。
        first = C.POINTER(Interface)()
        err = C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(first), err):
            raise RuntimeError(err.value.decode(errors="replace"))
        result = []
        try:
            cur = first
            while cur:
                x = cur.contents
                result.append(
                    (
                        x.name.decode(),
                        (x.description or x.name).decode(errors="replace"),
                    )
                )
                cur = x.next
        finally:
            self.lib.pcap_freealldevs(first)
        return result

    def run(self, interface, expression, stop, callback, ready=lambda: None):
        # 打开指定接口并应用 BPF，通过回调交付报文，退出时释放句柄。
        err = C.create_string_buffer(256)
        h = self.lib.pcap_open_live(interface.encode(), 65535, 0, 100, err)
        if not h:
            raise RuntimeError(err.value.decode(errors="replace"))
        try:
            link = self.lib.pcap_datalink(h)
            if link not in (0, 1, 12, 108, 101):
                raise RuntimeError(f"不支持的链路类型 {link}，请选择以太网或回环接口")
            if expression.strip():
                program = Program()
                if self.lib.pcap_compile(
                    h, C.byref(program), expression.encode(), 1, 0xFFFFFFFF
                ):
                    raise RuntimeError(self.lib.pcap_geterr(h).decode(errors="replace"))
                try:
                    if self.lib.pcap_setfilter(h, C.byref(program)):
                        raise RuntimeError(
                            self.lib.pcap_geterr(h).decode(errors="replace")
                        )
                finally:
                    self.lib.pcap_freecode(C.byref(program))
            if self.lib.pcap_setnonblock(h, 1, err):
                raise RuntimeError(err.value.decode(errors="replace"))
            ready()
            header = C.POINTER(Header)()
            data = C.POINTER(C.c_ubyte)()
            while not stop.is_set():
                n = self.lib.pcap_next_ex(h, C.byref(header), C.byref(data))
                if n == 1:
                    x = header.contents
                    callback(
                        x.sec + x.usec / 1e6,
                        C.string_at(data, x.caplen),
                        x.length,
                        link,
                    )
                elif n == 0:
                    stop.wait(0.01)
                elif n == -2:
                    break
                else:
                    raise RuntimeError(self.lib.pcap_geterr(h).decode(errors="replace"))
        finally:
            self.lib.pcap_close(h)
