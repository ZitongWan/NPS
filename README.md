# 雁栖湖网络嗅探器 · EX1A

课程：软件与安全  
姓名：万梓桐  
学号：202628015029010    
实验：1A 网络嗅探器

[阅读实验报告（含配图）](docs/万梓桐_202628015029010_ex1A_report.md)

## 运行

Windows 需安装带 Tkinter 的 64 位 Python 和 Npcap。已在 Python 3.8.20 与 3.11.7 下验证；程序使用 Python 标准库，无须第三方 Python 包。若 Npcap 限制了捕获权限，需要在管理员终端启动。

在已准备好的 Python 环境中，进入源码目录执行：

```text
python app.py
```

本机使用 Conda 的 `stage4` 环境，先执行 `conda activate stage4`；其他电脑使用自己配置好的环境，无须使用相同名称。后续命令中的 `python` 均指当前环境的解释器。

`启动.bat` 是可选入口，调用 Windows Python 启动器 `py -3`，不会自动激活 Conda 环境。

离线查看：点击“导入 PCAP”，选择 `samples/local_http.pcap`；显示过滤填 `http`，点击“应用”，选中报文查看协议字段、原始字节及 TCP 双向流。

## 手动抓包演示

1. 在源码目录打开终端 A，启动本地服务：

   ```text
   python -m http.server 8080 --bind 127.0.0.1 --directory samples
   ```

2. 在嗅探器选择 `Adapter for loopback traffic capture`，捕获过滤填写 `tcp port 8080 and host 127.0.0.1`，点击“开始抓包”。
3. 在终端 B 发起请求；每次执行产生一组请求相关报文，总包数可能变化：

   ```text
   C:\Windows\System32\curl.exe --noproxy "*" -sS -o NUL -w "HTTP status: %{http_code}\n" http://127.0.0.1:8080/test_results_20261119.txt
   ```

4. 点击“停止”，等待状态栏变为“已停止”；显示过滤填 `http` 并点击“应用”，核对 GET 和响应。
5. 选中 HTTP 报文，点击“查看 TCP 流”，观察握手、seq/ack、标志和请求响应内容。
6. 点击“导出全部 PCAP”保存，再导入该文件核对数量。显示过滤只影响列表，导出保留全部已捕获报文。
7. 在终端 A 按 Ctrl+C 关闭服务。

## 自动验证

在源码目录执行：

```text
python -m unittest -v
python local_validation.py
```

第一条运行 31 项测试，不访问外部网络；界面状态测试使用控件替身。第二条调用 Npcap 实际捕获三次本机 HTTP 请求，检查请求响应、过滤范围及停止行为，默认输出到 `validation_output/`。可使用 `--output-dir` 指定其他目录，`samples/` 原始样例目录受保护。

- `samples/local_http.pcap`、`validation.json`：11 月 10 日原始实验，39 包、6 个 HTTP 报文；报告图表使用这份记录。
- `samples/revalidation_20261119.pcap`、`revalidation_20261119.json`：11 月 19 日复测，40 包、6 个 HTTP 报文。
- `samples/test_results_20261119.txt`：本轮 31 项测试输出。`test_results.txt` 保留原始 19 项测试记录。

- `samples/test_results_stage4_20261119.txt` 与 `samples/stage4_validation_20261119.*`：Python 3.8.20 环境中的 31 项测试输出及真实抓包记录。

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

报告及配图保存在 `docs/` 目录，下载或移动 Markdown 文档时需一并保留其中的 `assets/` 文件夹。代码、测试和文稿编写使用了 AI 辅助工具。
