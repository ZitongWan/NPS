import collections
import datetime
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from protocol import decode, display_filter, save_pcap, load_pcap, flow_text
from capture import Npcap


class App:
    def __init__(self, root):
        # 初始化采集状态，创建过滤栏、报文列表和协议详情区域。
        self.root = root
        root.title("雁栖湖网络嗅探器 · EX1A")
        root.geometry("1200x780")
        self.packets = []
        self.counts = collections.Counter()
        self.q = queue.Queue(2000)
        self.stop = threading.Event()
        self.thread = None
        self.dropped = 0
        self.error = ""
        self.predicate = lambda p: True
        self.npcap = None
        self.devices = []
        self.applied_search = ""
        self.iface = tk.StringVar()
        self.bpf = tk.StringVar()
        self.expr = tk.StringVar()
        self.search = tk.StringVar()
        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="网卡").pack(side="left")
        self.combo = ttk.Combobox(
            top, textvariable=self.iface, width=75, state="readonly"
        )
        self.combo.pack(side="left", padx=8)
        ttk.Button(top, text="刷新网卡", command=self.refresh).pack(side="left")
        self.startbutton = ttk.Button(top, text="开始抓包", command=self.start)
        self.startbutton.pack(side="left", padx=8)
        ttk.Button(top, text="停止", command=self.stop.set).pack(side="left")
        bar = ttk.Frame(root, padding=8)
        bar.pack(fill="x")
        ttk.Label(bar, text="捕获过滤 BPF").pack(side="left")
        ttk.Entry(bar, textvariable=self.bpf, width=36).pack(side="left", padx=5)
        ttk.Label(bar, text="显示过滤").pack(side="left")
        ttk.Entry(bar, textvariable=self.expr, width=28).pack(side="left", padx=5)
        ttk.Label(bar, text="文本查找").pack(side="left")
        ttk.Entry(bar, textvariable=self.search, width=18).pack(side="left", padx=5)
        ttk.Button(bar, text="应用", command=self.apply_filter).pack(side="left")
        ttk.Label(
            root,
            text="过滤示例：捕获过滤 tcp port 8080；显示过滤 (tcp or udp) and ipv4",
            padding=(8, 0),
        ).pack(anchor="w")
        actions = ttk.Frame(root, padding=8)
        actions.pack(fill="x")
        for label, fn in [
            ("导入 PCAP", self.open),
            ("导出全部 PCAP", self.save),
            ("查看 TCP 流", self.follow),
            ("清空", self.clear),
        ]:
            ttk.Button(actions, text=label, command=fn).pack(side="left", padx=3)
        self.status = tk.StringVar(value="就绪")
        self.status_label = ttk.Label(root, textvariable=self.status, padding=8)
        self.status_label.pack(side="bottom", fill="x")
        panes = ttk.Panedwindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8)
        frame = ttk.Frame(panes)
        panes.add(frame, weight=3)
        columns = ("id", "time", "src", "dst", "protocol", "length", "info")
        self.table = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        for name, width, label in zip(
            columns,
            (48, 110, 180, 180, 75, 65, 380),
            ("序号", "时间", "源地址", "目的地址", "协议", "长度", "摘要"),
        ):
            self.table.heading(name, text=label)
            self.table.column(name, width=width, minwidth=45)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=self.table.xview)
        self.table.configure(xscrollcommand=horizontal.set)
        horizontal.pack(side="bottom", fill="x")
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        tabs = ttk.Notebook(panes)
        panes.add(tabs, weight=2)
        self.detail = ScrolledText(tabs, wrap="word", font=("Consolas", 11))
        self.hex = ScrolledText(tabs, wrap="word", font=("Consolas", 10))
        tabs.add(self.detail, text="协议字段")
        tabs.add(self.hex, text="原始字节 HEX / ASCII")
        self.table.bind("<<TreeviewSelect>>", self.select)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()
        root.after(100, self.poll)

    def refresh(self):
        # 重新枚举网卡，并在初始化失败时显示驱动错误信息。
        try:
            self.npcap = Npcap()
            self.devices = self.npcap.interfaces()
            self.combo["values"] = [
                f"{i+1}. {desc}" for i, (_, desc) in enumerate(self.devices)
            ]
            if self.devices:
                self.combo.current(0)
        except Exception as e:
            self.status.set("实时抓包不可用；仍可导入 PCAP。" + str(e))

    def active(self):
        # 根据采集线程状态判断是否仍在抓包。
        return self.thread is not None and self.thread.is_alive()

    def clear(self):
        # 停止采集后清空报文、待处理队列及详情显示。
        if self.active():
            messagebox.showinfo("提示", "请先停止抓包")
            return
        self.packets.clear()
        self.counts.clear()
        self.table.delete(*self.table.get_children())
        self.dropped = 0
        while True:
            try:
                self.q.get_nowait()
            except queue.Empty:
                break
        self.clear_details()

    def clear_details(self):
        # 列表重建或取消选择时清空详情，避免保留上一条报文的信息。
        for text in (self.detail, self.hex):
            text.delete("1.0", "end")

    def start(self):
        # 检查接口选择并启动后台线程，将采集任务与界面操作分开。
        if self.active():
            return
        if not self.npcap or self.combo.current() < 0:
            messagebox.showerror("错误", "请先安装 Npcap 并选择网卡")
            return
        self.clear()
        self.error = ""
        self.stop.clear()
        interface = self.devices[self.combo.current()][0]
        expression = self.bpf.get()

        def callback(ts, raw, wire, link):
            # 将原始报文放入队列，队列已满时累计应用丢弃数量。
            try:
                self.q.put_nowait((ts, raw, wire, link))
            except queue.Full:
                self.dropped += 1

        def worker():
            # 执行实时采集，并将异常交给界面线程显示。
            try:
                self.npcap.run(interface, expression, self.stop, callback)
            except Exception as e:
                self.error = str(e)

        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()

    def visible(self, p):
        # 同时检查协议过滤和文本查找，确定报文是否显示。
        key = self.applied_search
        return self.predicate(p) and (
            not key or key in f"{p.src} {p.dst} {p.info}".lower()
        )

    def insert(self, index, p):
        # 将匹配过滤条件的报文摘要添加到列表。
        if self.visible(p):
            stamp = datetime.datetime.fromtimestamp(p.time).strftime("%H:%M:%S.%f")[:-3]
            self.table.insert(
                "",
                "end",
                iid=str(index),
                values=(index + 1, stamp, p.src, p.dst, p.protocol, p.wirelen, p.info),
            )

    def poll(self):
        # 在主线程中批量处理队列，更新列表、统计信息和按钮状态。
        for _ in range(150):
            try:
                args = self.q.get_nowait()
            except queue.Empty:
                break
            if len(self.packets) >= 5000:
                self.stop.set()
                self.dropped += 1
                continue
            p = decode(*args)
            self.packets.append(p)
            self.counts[p.protocol] += 1
            self.insert(len(self.packets) - 1, p)
            if len(self.packets) >= 5000:
                self.stop.set()
        if self.error:
            messagebox.showerror("捕获错误", self.error)
            self.error = ""
        state = "捕获中" if self.active() else "已停止"
        self.startbutton.configure(state="disabled" if self.active() else "normal")
        self.status.set(
            f"{state} | 已保留 {len(self.packets)} / 5000 包 | 应用丢弃 {self.dropped} | "
            + "  ".join(f"{k}:{v}" for k, v in self.counts.items())
        )
        self.root.after(100, self.poll)

    def apply_filter(self):
        # 应用当前过滤条件，并重新筛选已经保存的报文。
        try:
            self.predicate = display_filter(self.expr.get())
        except (ValueError, SyntaxError) as e:
            messagebox.showerror("过滤表达式错误", str(e))
            return False
        self.applied_search = self.search.get().lower()
        self.rebuild_table()
        return True

    def rebuild_table(self):
        # 使用已经生效的筛选条件重建列表，并清空旧选择的详情。
        self.table.delete(*self.table.get_children())
        self.clear_details()
        for i, p in enumerate(self.packets):
            self.insert(i, p)

    def selected(self):
        # 使用列表行的编号取出对应的报文对象。
        ids = self.table.selection()
        return self.packets[int(ids[0])] if ids else None

    def select(self, event=None):
        # 同步显示选中报文的协议字段、十六进制字节和 ASCII 内容。
        p = self.selected()
        self.clear_details()
        if p is None:
            return
        self.detail.insert(
            "end",
            f"捕获长度={len(p.raw)} 线上长度={p.wirelen} 链路类型={p.link}\n"
            + "\n".join(p.details),
        )
        lines = []
        for i in range(0, len(p.raw), 16):
            part = p.raw[i : i + 16]
            ascii = "".join(chr(v) if 32 <= v < 127 else "." for v in part)
            lines.append(f'{i:04x}  {part.hex(" "):<47}  {ascii}')
        self.hex.insert("end", "\n".join(lines))

    def follow(self):
        # 在独立窗口中展示选中报文所属的双向 TCP 报文组。
        p = self.selected()
        if p is None:
            return
        win = tk.Toplevel(self.root)
        win.title("TCP 双向流")
        win.geometry("950x600")
        text = ScrolledText(win, wrap="word", font=("Consolas", 11))
        text.pack(fill="both", expand=True)
        text.insert("end", flow_text(self.packets, p))

    def open(self):
        # 成功读取整个 PCAP 文件后，再替换当前报文列表。
        if self.active():
            messagebox.showinfo("提示", "请先停止抓包")
            return
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap"), ("全部", "*.*")])
        if not path:
            return
        try:
            predicate = display_filter(self.expr.get())
            packets = list(load_pcap(path))
            self.clear()
            self.packets = packets
            self.counts.update(p.protocol for p in packets)
            self.predicate = predicate
            self.applied_search = self.search.get().lower()
            self.rebuild_table()
        except Exception as e:
            messagebox.showerror("导入失败", str(e))

    def save(self):
        # 将全部已保留报文导出到用户指定的 PCAP 文件。
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")]
        )
        if path:
            try:
                save_pcap(path, self.packets)
            except Exception as e:
                messagebox.showerror("保存失败", str(e))

    def close(self):
        # 先通知采集线程停止，等待其退出后关闭界面。
        self.stop.set()
        if self.active():
            self.root.after(50, self.close)
        else:
            self.root.destroy()


if __name__ == "__main__":
    try:
        import ctypes

        ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    app = App(root)
    root.mainloop()
