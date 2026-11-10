"""Yanqi Sniffer: Python 3.10+, Tkinter and Npcap. No third-party Python modules."""
import collections
import datetime
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from protocol import decode, display_filter, save_pcap, load_pcap, flow_text
from capture import Npcap

class App:
    def __init__(self,root):
        self.root=root;root.title('雁栖湖网络嗅探器 · EX1A');root.geometry('1200x780')
        self.packets=[];self.q=queue.Queue(2000);self.stop=threading.Event();self.thread=None
        self.dropped=0;self.error='';self.predicate=lambda p:True;self.npcap=None;self.devices=[]
        self.iface=tk.StringVar();self.bpf=tk.StringVar();self.expr=tk.StringVar();self.search=tk.StringVar()
        top=ttk.Frame(root,padding=8);top.pack(fill='x')
        ttk.Label(top,text='网卡').pack(side='left')
        self.combo=ttk.Combobox(top,textvariable=self.iface,width=75,state='readonly');self.combo.pack(side='left',padx=8)
        ttk.Button(top,text='刷新网卡',command=self.refresh).pack(side='left')
        self.startbutton=ttk.Button(top,text='开始抓包',command=self.start);self.startbutton.pack(side='left',padx=8)
        ttk.Button(top,text='停止',command=self.stop.set).pack(side='left')
        bar=ttk.Frame(root,padding=8);bar.pack(fill='x')
        ttk.Label(bar,text='捕获过滤 BPF').pack(side='left');ttk.Entry(bar,textvariable=self.bpf,width=36).pack(side='left',padx=5)
        ttk.Label(bar,text='显示过滤').pack(side='left');ttk.Entry(bar,textvariable=self.expr,width=28).pack(side='left',padx=5)
        ttk.Label(bar,text='文本查找').pack(side='left');ttk.Entry(bar,textvariable=self.search,width=18).pack(side='left',padx=5)
        ttk.Button(bar,text='应用',command=self.apply_filter).pack(side='left')
        ttk.Label(root,text='示例：BPF = tcp port 8080；显示 = (tcp or udp) and ipv4；只捕获本人或已获授权的流量。',padding=(8,0)).pack(anchor='w')
        actions=ttk.Frame(root,padding=8);actions.pack(fill='x')
        for label,fn in [('导入 PCAP',self.open),('导出全部 PCAP',self.save),('查看 TCP 流',self.follow),('清空',self.clear)]:
            ttk.Button(actions,text=label,command=fn).pack(side='left',padx=3)
        panes=ttk.Panedwindow(root,orient='vertical');panes.pack(fill='both',expand=True,padx=8)
        frame=ttk.Frame(panes);panes.add(frame,weight=3)
        columns=('id','time','src','dst','protocol','length','info')
        self.table=ttk.Treeview(frame,columns=columns,show='headings',height=15)
        for name,width,label in zip(columns,(48,110,180,180,75,65,380),('序号','时间','源地址','目的地址','协议','长度','摘要')):
            self.table.heading(name,text=label);self.table.column(name,width=width,minwidth=45)
        scroll=ttk.Scrollbar(frame,orient='vertical',command=self.table.yview);self.table.configure(yscrollcommand=scroll.set)
        horizontal=ttk.Scrollbar(frame,orient='horizontal',command=self.table.xview)
        self.table.configure(xscrollcommand=horizontal.set)
        horizontal.pack(side='bottom',fill='x')
        self.table.pack(side='left',fill='both',expand=True);scroll.pack(side='right',fill='y')
        tabs=ttk.Notebook(panes);panes.add(tabs,weight=2)
        self.detail=tk.Text(tabs,wrap='word',font=('Consolas',11));self.hex=tk.Text(tabs,wrap='none',font=('Consolas',10))
        tabs.add(self.detail,text='协议字段');tabs.add(self.hex,text='原始字节 HEX / ASCII')
        self.status=tk.StringVar(value='就绪');ttk.Label(root,textvariable=self.status,padding=8).pack(anchor='w')
        self.table.bind('<<TreeviewSelect>>',self.select)
        root.protocol('WM_DELETE_WINDOW',self.close)
        self.refresh();root.after(100,self.poll)

    def refresh(self):
        try:
            self.npcap=Npcap();self.devices=self.npcap.interfaces()
            self.combo['values']=[f'{i+1}. {desc}' for i,(_,desc) in enumerate(self.devices)]
            if self.devices:self.combo.current(0)
        except Exception as e:self.status.set('实时抓包不可用；仍可导入 PCAP。'+str(e))

    def active(self):return self.thread is not None and self.thread.is_alive()
    def clear(self):
        if self.active():messagebox.showinfo('提示','请先停止抓包');return
        self.packets.clear();self.table.delete(*self.table.get_children());self.dropped=0
        while True:
            try:self.q.get_nowait()
            except queue.Empty:break
        for text in (self.detail,self.hex):text.delete('1.0','end')
    def start(self):
        if self.active():return
        if not self.npcap or self.combo.current()<0:messagebox.showerror('错误','请先安装 Npcap 并选择网卡');return
        self.clear();self.error='';self.stop.clear()
        interface=self.devices[self.combo.current()][0];expression=self.bpf.get()
        def callback(ts,raw,wire,link):
            try:self.q.put_nowait((ts,raw,wire,link))
            except queue.Full:self.dropped+=1
        def worker():
            try:self.npcap.run(interface,expression,self.stop,callback)
            except Exception as e:self.error=str(e)
        self.thread=threading.Thread(target=worker,daemon=True);self.thread.start()
    def visible(self,p):
        key=self.search.get().lower()
        return self.predicate(p) and (not key or key in f'{p.src} {p.dst} {p.info}'.lower())
    def insert(self,index,p):
        if self.visible(p):
            stamp=datetime.datetime.fromtimestamp(p.time).strftime('%H:%M:%S.%f')[:-3]
            self.table.insert('', 'end',iid=str(index),values=(index+1,stamp,p.src,p.dst,p.protocol,p.wirelen,p.info))
    def poll(self):
        for _ in range(150):
            try:args=self.q.get_nowait()
            except queue.Empty:break
            if len(self.packets)>=5000:self.stop.set();self.dropped+=1;continue
            p=decode(*args);self.packets.append(p);self.insert(len(self.packets)-1,p)
        if self.error:
            messagebox.showerror('捕获错误',self.error);self.error=''
        counts=collections.Counter(p.protocol for p in self.packets)
        state='捕获中' if self.active() else '已停止'
        self.startbutton.configure(state='disabled' if self.active() else 'normal')
        self.status.set(f'{state} | 已保留 {len(self.packets)} / 5000 包 | 应用丢弃 {self.dropped} | '+ '  '.join(f'{k}:{v}' for k,v in counts.items()))
        self.root.after(100,self.poll)
    def apply_filter(self):
        try:self.predicate=display_filter(self.expr.get())
        except (ValueError,SyntaxError) as e:messagebox.showerror('过滤表达式错误',str(e));return
        self.table.delete(*self.table.get_children())
        for i,p in enumerate(self.packets):self.insert(i,p)
    def selected(self):
        ids=self.table.selection();return self.packets[int(ids[0])] if ids else None
    def select(self,event=None):
        p=self.selected()
        if p is None:return
        self.detail.delete('1.0','end');self.detail.insert('end',f'捕获长度={len(p.raw)} 线上长度={p.wirelen} 链路类型={p.link}\n'+'\n'.join(p.details))
        lines=[]
        for i in range(0,len(p.raw),16):
            part=p.raw[i:i+16];ascii=''.join(chr(v) if 32<=v<127 else '.' for v in part)
            lines.append(f'{i:04x}  {part.hex(" "):<47}  {ascii}')
        self.hex.delete('1.0','end');self.hex.insert('end','\n'.join(lines))
    def follow(self):
        p=self.selected()
        if p is None:return
        win=tk.Toplevel(self.root);win.title('TCP 双向流');win.geometry('950x600')
        text=tk.Text(win,wrap='word',font=('Consolas',11));text.pack(fill='both',expand=True)
        text.insert('end',flow_text(self.packets,p))
    def open(self):
        if self.active():messagebox.showinfo('提示','请先停止抓包');return
        path=filedialog.askopenfilename(filetypes=[('PCAP','*.pcap'),('全部','*.*')])
        if not path:return
        try:
            packets=list(load_pcap(path));self.clear();self.packets=packets;self.apply_filter()
        except Exception as e:messagebox.showerror('导入失败',str(e))
    def save(self):
        path=filedialog.asksaveasfilename(defaultextension='.pcap',filetypes=[('PCAP','*.pcap')])
        if path:
            try:save_pcap(path,self.packets)
            except Exception as e:messagebox.showerror('保存失败',str(e))
    def close(self):
        self.stop.set()
        if self.active():self.root.after(50,self.close)
        else:self.root.destroy()

if __name__=='__main__':
    try:
        import ctypes
        ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError,OSError):pass
    root=tk.Tk();app=App(root);root.mainloop()
