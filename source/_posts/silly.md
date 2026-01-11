title: Just being silly
date: 2026-01-11 12:00:00
tags:
  - SSH
  - Linux
  - Network
categories:
  - 技术
  - 折腾日志
---

在这个云计算和 CDN 追求“毫秒级”响应的时代，我决定反其道而行之。

手里有一台位于洛杉矶（LA）的 VPS，平时用来跑 Caddy 反代和做一些 Web 服务。众所周知，从国内直连 LA 的延迟本来就是“看脸”的（平均 200ms-400ms）。

看着终端里的光标闪烁，我突然冒出一个极其“Silly”的想法：**既然 SSH 可以端口转发，那我能不能把流量在我和 VPS 之间像打乒乓球一样来回弹射，直到把延迟堆到令人发指的程度？**

说干就干，我开启了一场关于 **TCP Meltdown（TCP 崩溃）** 的实地观测实验。

<!-- more -->

## 实验原理：网络套娃

正常的反向代理（1 Hop）：
> 用户 -> VPS -> 我的电脑 -> 返回

我构建的“智障”链路（3 Hop Loop）：
> 用户 -> VPS (端口8888) 
> -> 隧道下行 -> 我的电脑 (端口9001) 
> -> 隧道上行 -> VPS (端口9002) 
> -> 隧道下行 -> 我的电脑 (端口3001) 
> -> **终于到达 Web 服务**

这就像是你点了外卖，外卖小哥到了你家楼下，又跑回商家，商家又让他送一次，他又跑回商家，最后才把饭给你送到门口。

## 工具链

为了实现这个想法并将其可视化，我祭出了以下工具：

1.  **Caddy**: 作为入口，负责 SSL 和域名分流。
2.  **Autossh**: 负责维持那条摇摇欲坠的、包含多次转发的 SSH 隧道。
3.  **Python + Chart.js**: 写了一个简单的 HTTP 服务和前端面板，实时绘制延迟曲线。

### 1. 极其显眼的 SSH 命令

这是整个实验的核心，一段让人看了会觉得“这人是不是疯了”的端口映射配置：

```bash
autossh -M 0 -N \
  -o "ServerAliveInterval 30" \
  -o "ServerAliveCountMax 3" \
  -R 4000:localhost:3001 \      # 正常链路 (对照组)
  -R 8888:localhost:9001 \      # 入口
  -L 9001:localhost:9002 \      # 第一跳：回传给 VPS
  -R 9002:localhost:3001 \      # 第二跳：再次传回给 PC
  root@dmit
```

### 2. 可视化面板

为了直观地感受**卡顿**，我写了一个网页，它可以同时 Ping 正常链路和“智障链路”，并用 Chart.js 画图。

```python
import http.server
import socketserver
import json

# --- CONFIGURATION ---
PORT = 3001
# ---------------------

# We inject the HTML and JS directly comfortably here
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Lag-o-Meter Chart</title>
    <!-- Import Chart.js from CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .container { border: 1px solid #30363d; padding: 20px; border-radius: 10px; background: #161b22; box-shadow: 0 0 20px rgba(0,0,0,0.5); text-align: center; max-width: 800px; width: 95%; }
        h1 { color: #58a6ff; margin-bottom: 5px; }
        p { color: #8b949e; margin-top: 0; }
        .btn { background: #238636; color: white; border: none; padding: 10px 20px; font-size: 1rem; cursor: pointer; border-radius: 6px; margin: 10px 5px; font-family: inherit; transition: 0.2s; }
        .btn:hover { background: #2ea043; }
        .btn.stop { background: #da3633; }
        .btn.stop:hover { background: #b62324; }

        /* Chart Container */
        .chart-box { position: relative; height: 400px; width: 100%; margin-top: 20px; }

        .stats { display: flex; justify-content: space-around; margin-top: 10px; font-size: 0.9rem; }
        .stat-box span { display: block; font-size: 1.5rem; font-weight: bold; }
        .green { color: #3fb950; }
        .red { color: #f85149; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSH Tunnel Jitter Monitor</h1>
        <p>Comparing 1-Hop vs Multi-Hop Latency</p>

        <div class="controls">
            <button id="toggleBtn" class="btn" onclick="toggleMonitor()">Start Live Monitor</button>
        </div>

        <div class="stats">
            <div class="stat-box green">Normal: <span id="latest-fast">--</span></div>
            <div class="stat-box red">Silly: <span id="latest-silly">--</span></div>
        </div>

        <div class="chart-box">
            <canvas id="lagChart"></canvas>
        </div>
    </div>

    <script>
        // --- EDIT YOUR DOMAINS HERE ---
        const FAST_URL = 'https://fast.woftom.online/ping';
        const SILLY_URL = 'https://silly.woftom.online/ping';
        // ------------------------------

        let isRunning = false;
        let chart;
        let frameCount = 0;

        // Initialize Chart
        function initChart() {
            const ctx = document.getElementById('lagChart').getContext('2d');

            // Gradient for the silly line to make it look cool/dangerous
            let gradient = ctx.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(248, 81, 73, 0.5)');
            gradient.addColorStop(1, 'rgba(248, 81, 73, 0)');

            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Fast Lane (1 Hop)',
                            borderColor: '#3fb950',
                            backgroundColor: '#3fb950',
                            borderWidth: 2,
                            tension: 0.3,
                            pointRadius: 0,
                            data: []
                        },
                        {
                            label: 'Silly Lane (Multi-Hop)',
                            borderColor: '#f85149',
                            backgroundColor: gradient,
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4, // Makes the line curvy/chaotic
                            pointRadius: 3,
                            data: []
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false, // Turn off animation for instant updates
                    scales: {
                        x: { display: false }, // Hide x-axis labels for clean look
                        y: {
                            beginAtZero: true,
                            grid: { color: '#30363d' },
                            ticks: { color: '#8b949e' },
                            title: { display: true, text: 'Latency (ms)', color: '#8b949e' }
                        }
                    },
                    plugins: {
                        legend: { labels: { color: '#c9d1d9' } }
                    }
                }
            });
        }

        async function measure(url) {
            const start = performance.now();
            try {
                // We add ?t=timestamp to prevent Browser Caching
                await fetch(url + '?t=' + Date.now(), {cache: "no-store"});
                const end = performance.now();
                return parseInt(end - start);
            } catch (e) {
                console.error(e);
                return null; // Return null on timeout/error
            }
        }

        async function loop() {
            if (!isRunning) return;

            // Measure both
            // We run them in parallel (Promise.all) to stress test,
            // OR sequentially to be accurate. Let's do sequential to avoid blocking.
            const fastTime = await measure(FAST_URL);
            const sillyTime = await measure(SILLY_URL);

            // Update Text
            if(fastTime) document.getElementById('latest-fast').innerText = fastTime + "ms";
            if(sillyTime) document.getElementById('latest-silly').innerText = sillyTime + "ms";

            // Update Chart Data
            const nowLabel = frameCount++;

            // Add new data
            chart.data.labels.push(nowLabel);
            chart.data.datasets[0].data.push(fastTime || 0);
            chart.data.datasets[1].data.push(sillyTime || 0);

            // Remove old data to create scrolling effect (keep last 50 points)
            if (chart.data.labels.length > 50) {
                chart.data.labels.shift();
                chart.data.datasets[0].data.shift();
                chart.data.datasets[1].data.shift();
            }

            chart.update();

            // Loop every 1 second
            setTimeout(loop, 1000);
        }

        function toggleMonitor() {
            const btn = document.getElementById('toggleBtn');
            if (isRunning) {
                isRunning = false;
                btn.innerText = "Start Live Monitor";
                btn.classList.remove('stop');
            } else {
                isRunning = true;
                btn.innerText = "Stop Monitor";
                btn.classList.add('stop');
                loop();
            }
        }

        // Start chart on load
        initChart();
    </script>
</body>
</html>
"""

class CORSRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html" if self.path == "/" else "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        if self.path == "/ping":
            self.wfile.write(json.dumps({"status": "pong"}).encode())
        else:
            self.wfile.write(HTML_PAGE.encode())

print(f"Lag-o-Meter Dashboard running on port {PORT}...")
http.server.HTTPServer(('0.0.0.0', PORT), CORSRequestHandler).serve_forever()
```
## 实验结果：令人窒息的波形

启动服务，打开浏览器，我不禁为眼前的景象倒吸一口凉气。

![Lag Chart Visualization](/image/lag-chart.png)

### 数据解读

1.  **基础延迟 (绿色)**：**414ms**。
    *   这就是跨越太平洋的物理代价，本身就不快。
2.  **套娃延迟 (红色)**：**2300ms (2.3秒)**。
    *   你没看错，仅仅增加了几个 SSH 转发，延迟翻了 5 倍以上。

### 有趣的发现：Bufferbloat (缓冲区膨胀)

注意看红色的曲线，它呈现出一种非常诡异的**高原-峡谷**模式：

*   **高原期 (The Plateau)**：延迟稳定在 2400ms 左右，且非常平通过。这代表网络发生了 **拥塞 (Congestion)**。因为我在一条 TCP 连接（SSH）里塞入了另一条 TCP 连接（HTTP），产生了大名鼎鼎的 **TCP Meltdown**。数据包在 SSH 的缓冲区里排队，像早晚高峰。
*   **峡谷期 (The Dip)**：偶尔延迟会骤降到 1500ms。这是因为缓冲区被清空（Flushed）了，那个幸运的数据包没有排队，仅仅跑完了物理距离。

简单来说：**1.5秒是物理极限，多出来的 0.8秒纯粹是 CPU 在加密解密和数据排队的时间。**

## 总结

我为什么要做这个？
为了测试 VPS 性能？为了测试 `autossh` 的稳定性？

不，只是为了看着那个小球在屏幕上画出红色的波浪，感受那种**完全由自己一手掌握的混乱**。

如果你觉得你的网速太快了，生活太枯燥了，欢迎尝试这种“电子坐牢”体验。
