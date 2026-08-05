"""
Security Assessment Agent v2.0
Real-Time Monitor Dashboard
Left: System Stats | Right: Live Logs (tail -f)
"""

import os
import sys
import time
import socket
import threading
from datetime import datetime

try:
    import psutil
except ImportError:
    print("pip install psutil")
    sys.exit(1)

try:
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    from rich.console import Console
    from rich import box
except ImportError:
    print("pip install rich")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None


# ════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'monitor_logs.txt')
MAX_LOG_LINES = 200


# ════════════════════════════════════════════════════
#  STATS COLLECTOR
# ════════════════════════════════════════════════════
class StatsCollector:
    def __init__(self):
        self.cpu_percent = 0.0
        self.per_core_cpu = []
        self.memory = None
        self.swap = None
        self.disk = None
        self.net_io = None
        self.prev_net_io = None
        self.net_sent_speed = 0.0
        self.net_recv_speed = 0.0
        self.boot_time = 0
        self.process_count = 0
        self.scanner_cpu = 0.0
        self.scanner_mem = 0.0
        self.scanner_pid = os.getpid()
        self.public_ip = 'Fetching...'
        self.private_ip = 'Fetching...'
        self.hostname = 'Fetching...'

        self.cpu_history = [0.0] * 30
        self.mem_history = [0.0] * 30
        self.net_send_history = [0.0] * 30
        self.net_recv_history = [0.0] * 30

        self._running = True
        self._thread = threading.Thread(
            target=self._collect_loop, daemon=True
        )
        self._thread.start()

        self._ip_thread = threading.Thread(
            target=self._fetch_ip_info, daemon=True
        )
        self._ip_thread.start()

    def _collect_loop(self):
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(
            interval=None, percpu=True
        )
        self.prev_net_io = psutil.net_io_counters()

        while self._running:
            try:
                self._update_stats()
            except Exception:
                pass

    def _update_stats(self):
        self.cpu_percent = psutil.cpu_percent(
            interval=None
        )
        self.per_core_cpu = psutil.cpu_percent(
            interval=None, percpu=True
        )

        self.memory = psutil.virtual_memory()
        self.swap = psutil.swap_memory()
        self.disk = psutil.disk_usage('/')

        current_net = psutil.net_io_counters()
        if self.prev_net_io:
            self.net_sent_speed = (
                (
                    current_net.bytes_sent
                    - self.prev_net_io.bytes_sent
                ) / 1024.0
            )
            self.net_recv_speed = (
                (
                    current_net.bytes_recv
                    - self.prev_net_io.bytes_recv
                ) / 1024.0
            )
        self.prev_net_io = current_net
        self.net_io = current_net

        self.boot_time = psutil.boot_time()
        self.process_count = len(psutil.pids())

        try:
            proc = psutil.Process(self.scanner_pid)
            self.scanner_cpu = proc.cpu_percent(
                interval=None
            )
            self.scanner_mem = (
                proc.memory_info().rss / 1024 / 1024
            )
        except Exception:
            self.scanner_cpu = 0.0
            self.scanner_mem = 0.0

        self.cpu_history.append(self.cpu_percent)
        self.cpu_history = self.cpu_history[-30:]

        if self.memory:
            self.mem_history.append(
                self.memory.percent
            )
            self.mem_history = self.mem_history[-30:]

        self.net_send_history.append(
            self.net_sent_speed
        )
        self.net_send_history = (
            self.net_send_history[-30:]
        )
        self.net_recv_history.append(
            self.net_recv_speed
        )
        self.net_recv_history = (
            self.net_recv_history[-30:]
        )

    def _fetch_ip_info(self):
        try:
            s = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM
            )
            s.connect(('8.8.8.8', 80))
            self.private_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self.private_ip = '?.?.?.?'

        try:
            self.hostname = socket.gethostname()
        except Exception:
            self.hostname = 'unknown'

        if requests:
            for service in [
                'https://api.ipify.org',
                'https://ifconfig.me/ip',
                'https://icanhazip.com',
                'https://checkip.amazonaws.com',
            ]:
                try:
                    r = requests.get(
                        service, timeout=5
                    )
                    if r.status_code == 200:
                        self.public_ip = (
                            r.text.strip()
                        )
                        break
                except Exception:
                    continue
            else:
                self.public_ip = 'Unavailable'
        else:
            self.public_ip = 'N/A'

    def stop(self):
        self._running = False


# ════════════════════════════════════════════════════
#  SPARKLINE
# ════════════════════════════════════════════════════
def make_sparkline(values, width=25, color='green'):
    if not values or all(v == 0 for v in values):
        return Text('▁' * width, style=f'dim {color}')

    max_val = max(values) or 1
    blocks = '▁▂▃▄▅▆▇█'

    data = values[-width:]
    if len(data) < width:
        data = [0.0] * (width - len(data)) + data

    chars = []
    for v in data:
        idx = min(7, max(0, int((v / max_val) * 7)))
        chars.append(blocks[idx])

    return Text(''.join(chars), style=color)


# ════════════════════════════════════════════════════
#  PROGRESS BAR
# ════════════════════════════════════════════════════
def make_bar(percent, width=20):
    filled = int((percent / 100) * width)
    empty = width - filled

    if percent >= 80:
        color = 'red'
    elif percent >= 50:
        color = 'yellow'
    else:
        color = 'green'

    bar = '█' * filled + '░' * empty
    return Text(
        f'[{bar}] {percent:.1f}%', style=color
    )


# ════════════════════════════════════════════════════
#  LOG READER
# ════════════════════════════════════════════════════
def read_logs():
    try:
        if not os.path.exists(LOG_FILE):
            return ['Waiting for scan to start...']

        with open(
            LOG_FILE, 'r', encoding='utf-8',
            errors='ignore'
        ) as f:
            lines = f.readlines()

        cleaned = [
            l.rstrip('\n\r')
            for l in lines
            if l.strip()
        ]

        return cleaned[-MAX_LOG_LINES:]

    except PermissionError:
        return ['Log file locked...']
    except Exception as e:
        return [f'Log error: {e}']


# ════════════════════════════════════════════════════
#  LOG COLORIZER
# ════════════════════════════════════════════════════
def colorize_log_line(line):
    text = Text()

    parts = line.split(' ', 2)
    if len(parts) >= 2:
        timestamp = parts[0]
        level_and_msg = ' '.join(parts[1:])
    else:
        timestamp = ''
        level_and_msg = line

    if timestamp:
        text.append(
            timestamp + ' ', style='dim cyan'
        )

    if '[CRITICAL]' in line:
        text.append(
            level_and_msg,
            style='bold red on dark_red'
        )
    elif '[ERROR]' in line:
        text.append(
            level_and_msg, style='bold red'
        )
    elif '[BLOCK]' in line:
        text.append(
            level_and_msg, style='bold red'
        )
    elif '[ROTATE]' in line:
        text.append(
            level_and_msg,
            style='bold yellow on dark_red'
        )
    elif '[WARN]' in line:
        text.append(
            level_and_msg, style='yellow'
        )
    elif '[OK]' in line or '[SUCCESS]' in line:
        text.append(
            level_and_msg, style='green'
        )
    elif '[SCAN]' in line:
        text.append(
            level_and_msg, style='bold cyan'
        )
    elif '[AGENT]' in line:
        text.append(
            level_and_msg, style='magenta'
        )
    elif '[CONN]' in line:
        text.append(
            level_and_msg, style='blue'
        )
    elif '[SEC]' in line:
        text.append(
            level_and_msg, style='bold yellow'
        )
    elif '[GUARD]' in line:
        text.append(
            level_and_msg, style='cyan'
        )
    elif line.startswith('#'):
        text.append(
            level_and_msg, style='dim white'
        )
    else:
        text.append(
            level_and_msg, style='white'
        )

    return text


# ════════════════════════════════════════════════════
#  LEFT PANEL — SYSTEM STATS
# ════════════════════════════════════════════════════
def build_left_panel(stats):
    t = Table(
        show_header=False, box=None,
        padding=(0, 1), expand=True
    )
    t.add_column('l', style='bold white', width=14)
    t.add_column('v', style='cyan')

    # Network Identity
    t.add_row(
        Text('╔═ NETWORK ═╗', style='bold cyan'),
        Text('')
    )
    t.add_row(
        Text(' Hostname', style='white'),
        Text(str(stats.hostname), style='cyan')
    )
    t.add_row(
        Text(' Private IP', style='white'),
        Text(str(stats.private_ip), style='green')
    )
    pub_ip = str(stats.public_ip)
    pub_style = (
        'red' if pub_ip in [
            'Fetching...', 'Unavailable', 'N/A'
        ] else 'bold yellow'
    )
    t.add_row(
        Text(' Public IP', style='white'),
        Text(pub_ip, style=pub_style)
    )
    t.add_row(Text(''), Text(''))

    # CPU
    t.add_row(
        Text('╔═ CPU ═════╗', style='bold green'),
        Text('')
    )
    t.add_row(
        Text(' Overall', style='white'),
        make_bar(stats.cpu_percent)
    )
    if stats.per_core_cpu:
        for i, pct in enumerate(
            stats.per_core_cpu
        ):
            t.add_row(
                Text(
                    f' Core {i}', style='dim white'
                ),
                make_bar(pct, width=12)
            )
    t.add_row(
        Text(' History', style='dim white'),
        make_sparkline(
            stats.cpu_history, 25, 'green'
        )
    )
    t.add_row(Text(''), Text(''))

    # Memory
    t.add_row(
        Text('╔═ MEMORY ══╗', style='bold yellow'),
        Text('')
    )
    if stats.memory:
        mem = stats.memory
        t.add_row(
            Text(' RAM', style='white'),
            make_bar(mem.percent)
        )
        t.add_row(
            Text(' Used/Total', style='dim white'),
            Text(
                f'{mem.used/(1024**3):.1f}G / '
                f'{mem.total/(1024**3):.1f}G',
                style='white'
            )
        )
        t.add_row(
            Text(' Available', style='dim white'),
            Text(
                f'{mem.available/(1024**3):.1f}G',
                style='green'
            )
        )
    if stats.swap and stats.swap.total > 0:
        t.add_row(
            Text(' Swap', style='white'),
            make_bar(stats.swap.percent)
        )
    t.add_row(
        Text(' History', style='dim white'),
        make_sparkline(
            stats.mem_history, 25, 'yellow'
        )
    )
    t.add_row(Text(''), Text(''))

    # Disk
    t.add_row(
        Text('╔═ DISK ════╗', style='bold blue'),
        Text('')
    )
    if stats.disk:
        dk = stats.disk
        t.add_row(
            Text(' Usage', style='white'),
            make_bar(dk.percent)
        )
        t.add_row(
            Text(' Free', style='dim white'),
            Text(
                f'{dk.free/(1024**3):.0f}G',
                style='green'
            )
        )
    t.add_row(Text(''), Text(''))

    # Network I/O
    t.add_row(
        Text(
            '╔═ NETWORK IO ╗', style='bold magenta'
        ),
        Text('')
    )

    def fmt_speed(kb):
        if kb >= 1024:
            return f'{kb/1024:.1f} MB/s'
        return f'{kb:.1f} KB/s'

    send_s = stats.net_sent_speed
    recv_s = stats.net_recv_speed
    t.add_row(
        Text(' ↑ Upload', style='white'),
        Text(
            fmt_speed(send_s),
            style=(
                'red' if send_s > 500
                else 'yellow' if send_s > 100
                else 'green'
            )
        )
    )
    t.add_row(
        Text(' ↓ Download', style='white'),
        Text(
            fmt_speed(recv_s),
            style=(
                'red' if recv_s > 500
                else 'yellow' if recv_s > 100
                else 'green'
            )
        )
    )
    t.add_row(
        Text(' ↑ History', style='dim white'),
        make_sparkline(
            stats.net_send_history, 25, 'cyan'
        )
    )
    t.add_row(
        Text(' ↓ History', style='dim white'),
        make_sparkline(
            stats.net_recv_history, 25, 'magenta'
        )
    )
    t.add_row(Text(''), Text(''))

    # Scanner
    t.add_row(
        Text('╔═ SCANNER ═╗', style='bold red'),
        Text('')
    )
    t.add_row(
        Text(' PID', style='white'),
        Text(str(stats.scanner_pid), style='cyan')
    )
    t.add_row(
        Text(' CPU', style='white'),
        Text(
            f'{stats.scanner_cpu:.1f}%',
            style=(
                'red' if stats.scanner_cpu > 50
                else 'green'
            )
        )
    )
    t.add_row(
        Text(' Memory', style='white'),
        Text(
            f'{stats.scanner_mem:.1f} MB',
            style=(
                'red' if stats.scanner_mem > 500
                else 'green'
            )
        )
    )
    try:
        up = time.time() - stats.boot_time
        t.add_row(
            Text(' Uptime', style='white'),
            Text(
                f'{int(up//3600)}h {int((up%3600)//60)}m',
                style='dim white'
            )
        )
    except Exception:
        pass

    return Panel(
        t,
        title='[bold cyan]⚙ System Monitor[/]',
        border_style='cyan',
        box=box.ROUNDED,
        padding=(1, 1)
    )


# ════════════════════════════════════════════════════
#  RIGHT PANEL — LIVE LOGS (tail -f)
# ════════════════════════════════════════════════════
def build_right_panel():
    """
    tail -f style log viewer.
    Always shows latest lines.
    Auto-scrolls as new entries arrive.
    """
    logs = read_logs()

    # Calculate available display lines
    try:
        term_height = os.get_terminal_size().lines
    except Exception:
        term_height = 40

    available = max(10, term_height - 11)

    log_text = Text()

    if not logs or logs == [
        'Waiting for scan to start...'
    ]:
        log_text.append(
            '\n  ⏳ Waiting for scan...\n',
            style='dim yellow'
        )
        log_text.append(
            '  Run: python app.py\n',
            style='dim white'
        )
        log_text.append(
            '  Logs follow here (tail -f)\n',
            style='dim cyan'
        )
    else:
        # ✅ tail -f: Always last N lines
        tail = logs[-available:]

        for i, line in enumerate(tail):
            line_num = (
                len(logs) - len(tail) + i + 1
            )
            log_text.append(
                f'{line_num:>4} ',
                style='dim white'
            )
            log_text.append_text(
                colorize_log_line(line)
            )
            log_text.append('\n')

        # Blinking cursor = "live" indicator
        log_text.append(
            f'{"":>4} ', style='dim white'
        )
        log_text.append('█', style='bold green')

    # Stats for subtitle
    total = len(logs)
    showing = min(available, total)
    errors = sum(
        1 for l in logs
        if '[ERROR]' in l or '[CRITICAL]' in l
    )
    warns = sum(
        1 for l in logs if '[WARN]' in l
    )
    blocks = sum(
        1 for l in logs
        if '[BLOCK]' in l or '[ROTATE]' in l
    )

    parts = [f'tail -f', f'{showing}/{total}']
    if errors:
        parts.append(f'[red]{errors} err[/]')
    if warns:
        parts.append(f'[yellow]{warns} warn[/]')
    if blocks:
        parts.append(f'[red]{blocks} block[/]')

    return Panel(
        log_text,
        title='[bold green]📋 Live Logs[/]',
        subtitle=f'[dim]{" │ ".join(parts)}[/]',
        border_style='green',
        box=box.ROUNDED,
        padding=(0, 1)
    )


# ════════════════════════════════════════════════════
#  HEADER
# ════════════════════════════════════════════════════
def build_header():
    h = Text()
    h.append(
        '  ⚡ Security Assessment Agent ',
        style='bold cyan'
    )
    h.append('v2.0 ', style='bold white')
    h.append('│ ', style='dim white')
    h.append('Monitor ', style='bold green')
    h.append('│ ', style='dim white')
    h.append(
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        style='dim cyan'
    )
    h.append(' │ ', style='dim white')
    h.append('Ctrl+C exit', style='dim red')

    return Panel(
        h, border_style='cyan',
        box=box.HEAVY, padding=(0, 0)
    )


# ════════════════════════════════════════════════════
#  STATUS BAR
# ════════════════════════════════════════════════════
def build_status_bar(stats):
    now = datetime.now().strftime('%H:%M:%S')
    cpu = stats.cpu_percent
    mem = stats.memory.percent if stats.memory else 0

    if cpu > 90 or mem > 90:
        health = '🔴 CRITICAL'
        hs = 'bold red'
    elif cpu > 70 or mem > 70:
        health = '🟡 WARNING'
        hs = 'bold yellow'
    else:
        health = '🟢 HEALTHY'
        hs = 'bold green'

    pub = str(stats.public_ip)
    cs = (
        'dim white' if pub in [
            'Fetching...', 'Unavailable', 'N/A'
        ] else 'yellow'
    )

    st = Table(
        show_header=False, box=None,
        padding=(0, 2), expand=True
    )
    st.add_column(width=12)
    st.add_column(width=16)
    st.add_column(width=22)
    st.add_column(width=20)
    st.add_row(
        Text(f'⏰ {now}', style='cyan'),
        Text(health, style=hs),
        Text(f'🌐 {pub}', style=cs),
        Text(
            f'CPU:{cpu:.0f}% MEM:{mem:.0f}%',
            style='white'
        )
    )

    return Panel(
        st, border_style='dim white',
        box=box.SIMPLE, padding=(0, 0)
    )


# ════════════════════════════════════════════════════
#  LAYOUT
# ════════════════════════════════════════════════════
def build_layout(stats):
    layout = Layout()

    layout.split_column(
        Layout(name='header', size=3),
        Layout(name='body'),
        Layout(name='footer', size=3),
    )

    # Left 40% | Right 60%
    layout['body'].split_row(
        Layout(name='left', ratio=2),
        Layout(name='right', ratio=3),
    )

    layout['header'].update(build_header())
    layout['left'].update(
        build_left_panel(stats)
    )
    layout['right'].update(build_right_panel())
    layout['footer'].update(
        build_status_bar(stats)
    )

    return layout


# ════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════
def main():
    console = Console()
    console.clear()

    print(
        "\n  ⚡ Starting Monitor Dashboard...\n"
    )

    stats = StatsCollector()

    last_log_size = 0
    last_log_mtime = 0

    try:
        with Live(
            build_layout(stats),
            console=console,
            refresh_per_second=2,
            screen=True
        ) as live:
            while True:
                # Detect log file changes
                try:
                    if os.path.exists(LOG_FILE):
                        sz = os.path.getsize(LOG_FILE)
                        mt = os.path.getmtime(LOG_FILE)
                        if (
                            sz != last_log_size
                            or mt != last_log_mtime
                        ):
                            last_log_size = sz
                            last_log_mtime = mt
                except Exception:
                    pass

                live.update(build_layout(stats))

    except KeyboardInterrupt:
        stats.stop()
        console.clear()
        print(
            "\n  Monitor stopped. Goodbye!\n"
        )


if __name__ == '__main__':
    main()
