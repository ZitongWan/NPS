# 雁栖湖网络嗅探器 · EX1A

软件与系统安全课程实验 1A。姓名：ros；学号：202628015029010。

## 运行

Windows 安装带 Tkinter 的 64 位 Python 3.10 或以上，以及 Npcap。程序使用 Python 标准库，无须安装第三方 Python 包。若 Npcap 安装时限制了捕获权限，需要在管理员终端启动。

在源码目录双击 `启动.bat`，或在该目录的终端执行：

```text
py -3 app.py
```

离线查看不需要抓包权限：点击“导入 PCAP”，选择 `samples/local_http.pcap`；显示过滤填 `http`，点击“应用”，选中报文查看协议字段、原始字节及 TCP 双向流。

Conda 环境也可运行。已在 `stage4`（Python 3.8.20）中验证 31 项测试通过及真实回环抓包；随机字节测试兼容该版本。在 PyCharm 终端执行 `conda activate stage4` 后，使用 `python -m unittest -v`、`python app.py` 和 `python -m http.server 8080 --bind 127.0.0.1 --directory samples`，以确保使用激活环境的解释器。该环境的独立记录位于 `samples/test_results_stage4_20261119.txt` 与 `samples/stage4_validation_20261119.*`。

## 手动抓包演示

1. 在源码目录打开终端 A，启动本地服务：

   ```text
   py -3 -m http.server 8080 --bind 127.0.0.1 --directory samples
   ```

2. 在嗅探器选择 `Adapter for loopback traffic capture`，捕获过滤填写 `tcp port 8080 and host 127.0.0.1`，点击“开始抓包”。
3. 在终端 B 发起请求；每次执行产生一组请求相关报文，总包数可能变化：

   ```text
   C:\Windows\System32\curl.exe --noproxy "*" http://127.0.0.1:8080/test_results.txt
   ```

4. 点击“停止”，等待状态栏变为“已停止”；显示过滤填 `http` 并点击“应用”，核对 GET 和响应。
5. 选中 HTTP 报文，点击“查看 TCP 流”，观察握手、seq/ack、标志和请求响应内容。
6. 点击“导出全部 PCAP”保存，再导入该文件核对数量。显示过滤只影响列表，导出保留全部已捕获报文。
7. 在终端 A 按 Ctrl+C 关闭服务。

## 自动验证

在源码目录执行：

```text
py -3 -m unittest -v
py -3 local_validation.py
```

第一条运行 31 项测试，不访问外部网络；界面状态测试使用控件替身。第二条调用 Npcap 实际捕获三次本机 HTTP 请求，检查请求响应、过滤范围及停止行为，默认输出到 `validation_output/`。可使用 `--output-dir` 指定其他目录，`samples/` 原始样例目录受保护。

- `samples/local_http.pcap`、`validation.json`：11 月 10 日原始实验，39 包、6 个 HTTP 报文；报告图表使用这份记录。
- `samples/revalidation_20261119.pcap`、`revalidation_20261119.json`：11 月 19 日复测，40 包、6 个 HTTP 报文。
- `samples/test_results_20261119.txt`：本轮 31 项测试输出。`test_results.txt` 保留原始 19 项测试记录，用于手动 HTTP 演示。

## 文件与功能

| 文件 | 用途 |
| --- | --- |
| app.py | Tkinter 界面、采集线程、显示过滤与文件操作 |
| capture.py | ctypes 调用 Npcap、接口枚举及 BPF 捕获 |
| protocol.py | 分层解析、布尔过滤、PCAP 读写与双向报文归组 |
| test_protocol.py / test_regressions.py | 协议基础测试及文件保护、界面状态等回归测试 |
| local_validation.py | 本机回环真实抓包验证 |

支持 Ethernet/VLAN、ARP、IPv4/IPv6、TCP/UDP、ICMP，以及 HTTP/1 起始行和 DNS 头部识别。显示过滤示例：`http`、`tcp and ipv4`、`(tcp or udp) and not dns`。PCAP 导入支持经典 PCAP，不支持 PCAPNG。

TCP 流按双向端点归组，提供捕获顺序、相对时间和负载预览；尚未实现完整 TCP 重组、PID 归属及 TLS 解密。单次保留上限为 5000 包，应用丢弃计数不包含驱动丢包。

完整图文报告与配图位于课程材料包根目录。代码、测试和文稿编写使用了 AI 辅助工具。
