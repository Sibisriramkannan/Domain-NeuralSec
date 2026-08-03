"""
Live Security Scanner Monitor
Real-time CPU, Memory, Network + Logs
Auto-launched by app.py
"""

import os
import sys
import time
import psutil
import threading
from datetime import datetime
from collections import deque
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box

console = Console()

# ── Shared log queue ─────────────────────────────
LOG_FILE = 'monitor_logs.txt'
MAX_LOGS = 50
CPU_HISTORY = deque(maxlen=40)
MEM_HISTORY = deque(maxlen=40)
NET_SENT_PREV = [0]
NET_RECV_PREV = [0]
NET_SPEED_HISTORY = deque(maxlen=40)


# ════════════════════════════════════════════════════
#  SPARKLINE GRAPH
# ════════════════════════════════════════════════════
def make_sparkline(values, width=35, max_val=100):
    """Create ASCII sparkline graph"""
    if not values:
        return '─' * width

    blocks = ' ▁▂▃▄▅▆▇█'
    val_list = list(values)

    # Auto-scale if max_val is 0
    if max_val <= 0:
        max_val = max(val_list) if val_list else 1
        if max_val <= 0:
            max_val = 1

    normalized = []
    for v in val_list:
        idx = int((v / max_val) * 8)
        idx = max(0, min(8, idx))
        normalized.append(idx)

    # Pad to width
    while len(normalized) < width:
        normalized.insert(0, 0)
    normalized = normalized[-width:]

    return ''.join(blocks[n] for n in normalized)


def make_bar(value, max_val=100, width=25):
    """Create colored progress bar"""
    if max_val <= 0:
        max_val = 100
    ratio = value / max_val
    filled = int(ratio * width)
    filled = max(0, min(width, filled))
    bar = '█' * filled + '░' * (width - filled)

    if ratio < 0.50:
        color = 'green'
    elif ratio < 0.80:
        color = 'yellow'
    else:
        color = 'red'

    return f"[{color}]{bar}[/{color}]"


# ════════════════════════════════════════════════════
#  SYSTEM STATS COLLECTOR
# ════════════════════════════════════════════════════
class StatsCollector:
    """
    Collects system stats in background thread.
    Avoids blocking the UI render loop.
    """

    def __init__(self):
        self.stats = {}
        self.lock = threading.Lock()
        self.running = True

        # Initialize psutil cpu (first call
        # always returns 0)
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(
            interval=None, percpu=True
        )

        # Initialize network baseline
        net = psutil.net_io_counters()
        self.prev_sent = net.bytes_sent
        self.prev_recv = net.bytes_recv
        self.prev_time = time.time()

        # Initial collect
        self._collect()

        # Start background thread
        self.thread = threading.Thread(
            target=self._loop, daemon=True
        )
        self.thread.start()

    def _loop(self):
        """Background collection loop"""
        while self.running:
            self._collect()
            time.sleep(1.0)

    def _collect(self):
        """Collect all system stats"""
        try:
            # CPU - non-blocking
            cpu_pct = psutil.cpu_percent(
                interval=None
            )
            cpu_cores = psutil.cpu_percent(
                interval=None, percpu=True
            )
            cpu_freq = psutil.cpu_freq()
            cpu_count = psutil.cpu_count()

            # Memory
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Network speed calculation
            net = psutil.net_io_counters()
            now = time.time()
            dt = now - self.prev_time
            if dt > 0:
                send_speed = (
                    (net.bytes_sent - self.prev_sent)
                    / dt / 1024
                )  # KB/s
                recv_speed = (
                    (net.bytes_recv - self.prev_recv)
                    / dt / 1024
                )  # KB/s
            else:
                send_speed = 0
                recv_speed = 0

            self.prev_sent = net.bytes_sent
            self.prev_recv = net.bytes_recv
            self.prev_time = now

            # Connections
            try:
                net_conns = len(
                    psutil.net_connections()
                )
            except (
                psutil.AccessDenied,
                PermissionError
            ):
                net_conns = 0

            # Disk
            disk = psutil.disk_usage('/')

            # Current process
            try:
                proc = psutil.Process(os.getpid())
                proc_cpu = proc.cpu_percent()
                proc_mem = (
                    proc.memory_info().rss
                    / 1024 / 1024
                )
            except Exception:
                proc_cpu = 0
                proc_mem = 0

            with self.lock:
                self.stats = {
                    'cpu_percent': cpu_pct,
                    'cpu_per_core': cpu_cores,
                    'cpu_freq': (
                        cpu_freq.current
                        if cpu_freq else 0
                    ),
                    'cpu_count': cpu_count or 0,
                    'mem_percent': mem.percent,
                    'mem_used': (
                        mem.used / 1024**3
                    ),
                    'mem_total': (
                        mem.total / 1024**3
                    ),
                    'mem_available': (
                        mem.available / 1024**3
                    ),
                    'swap_percent': swap.percent,
                    'net_sent_total': (
                        net.bytes_sent / 1024**2
                    ),
                    'net_recv_total': (
                        net.bytes_recv / 1024**2
                    ),
                    'net_send_speed': send_speed,
                    'net_recv_speed': recv_speed,
                    'net_connections': net_conns,
                    'disk_percent': disk.percent,
                    'disk_used': (
                        disk.used / 1024**3
                    ),
                    'disk_total': (
                        disk.total / 1024**3
                    ),
                    'proc_cpu': proc_cpu,
                    'proc_mem': proc_mem,
                }

        except Exception:
            pass

    def get(self):
        """Get latest stats (thread-safe)"""
        with self.lock:
            return self.stats.copy()

    def stop(self):
        self.running = False


# ════════════════════════════════════════════════════
#  LOG READER
# ════════════════════════════════════════════════════
def read_logs():
    """Read latest logs from shared file"""
    logs = []
    try:
        if os.path.exists(LOG_FILE):
            with open(
                LOG_FILE, 'r', encoding='utf-8'
            ) as f:
                lines = f.readlines()
                logs = lines[-MAX_LOGS:]
    except Exception:
        pass
    return logs


# ════════════════════════════════════════════════════
#  BUILD LAYOUT
# ════════════════════════════════════════════════════
def build_layout(stats, logs):
    """Build the full monitor dashboard"""
    if not stats:
        return Panel(
            "[yellow]Waiting for data...[/]",
            title="Monitor"
        )

    now = datetime.now().strftime(
        '%Y-%m-%d %H:%M:%S'
    )

    # Update histories
    CPU_HISTORY.append(
        stats.get('cpu_percent', 0)
    )
    MEM_HISTORY.append(
        stats.get('mem_percent', 0)
    )
    NET_SPEED_HISTORY.append(
        stats.get('net_recv_speed', 0)
    )

    # ── Header ───────────────────────────────────
    header = Table.grid(expand=True)
    header.add_column(justify='left')
    header.add_column(justify='center')
    header.add_column(justify='right')
    header.add_row(
        "[bold cyan]SEC SCANNER MONITOR v1.0[/]",
        "[bold yellow]LIVE SYSTEM DASHBOARD[/]",
        f"[dim]{now}[/]"
    )

    # ── CPU Panel ────────────────────────────────
    cpu_t = Table(
        box=None, show_header=False,
        expand=True, padding=(0, 1)
    )
    cpu_t.add_column(width=14)
    cpu_t.add_column()

    cpu_pct = stats.get('cpu_percent', 0)
    cpu_bar = make_bar(cpu_pct)
    cpu_spark = make_sparkline(CPU_HISTORY)

    cpu_t.add_row(
        "[bold]Overall[/]",
        f"{cpu_bar} [bold cyan]"
        f"{cpu_pct:.1f}%[/]"
    )
    cpu_t.add_row(
        "[bold]Frequency[/]",
        f"[cyan]{stats.get('cpu_freq', 0):.0f}"
        f" MHz[/]"
    )
    cpu_t.add_row(
        "[bold]Cores[/]",
        f"[cyan]{stats.get('cpu_count', 0)}[/]"
    )
    cpu_t.add_row(
        "[bold]History[/]",
        f"[green]{cpu_spark}[/]"
    )

    # Per-core (max 8)
    cores = stats.get('cpu_per_core', [])
    if cores:
        cpu_t.add_row("", "")
        for i, core_pct in enumerate(cores[:8]):
            core_bar = make_bar(
                core_pct, width=12
            )
            cpu_t.add_row(
                f"  Core {i}",
                f"{core_bar} {core_pct:.0f}%"
            )

    cpu_panel = Panel(
        cpu_t,
        title="[bold green]⚡ CPU[/]",
        border_style="green",
        padding=(0, 1)
    )

    # ── Memory Panel ─────────────────────────────
    mem_t = Table(
        box=None, show_header=False,
        expand=True, padding=(0, 1)
    )
    mem_t.add_column(width=14)
    mem_t.add_column()

    mem_pct = stats.get('mem_percent', 0)
    mem_bar = make_bar(mem_pct)
    mem_spark = make_sparkline(MEM_HISTORY)

    mem_t.add_row(
        "[bold]RAM Usage[/]",
        f"{mem_bar} [bold cyan]"
        f"{mem_pct:.1f}%[/]"
    )
    mem_t.add_row(
        "[bold]Used[/]",
        f"[cyan]{stats.get('mem_used', 0):.2f}"
        f" / {stats.get('mem_total', 0):.2f}"
        f" GB[/]"
    )
    mem_t.add_row(
        "[bold]Available[/]",
        f"[green]"
        f"{stats.get('mem_available', 0):.2f}"
        f" GB[/]"
    )
    mem_t.add_row(
        "[bold]Swap[/]",
        f"[yellow]"
        f"{stats.get('swap_percent', 0):.1f}%[/]"
    )
    mem_t.add_row(
        "[bold]History[/]",
        f"[blue]{mem_spark}[/]"
    )

    mem_panel = Panel(
        mem_t,
        title="[bold blue]🧠 MEMORY[/]",
        border_style="blue",
        padding=(0, 1)
    )

    # ── Network Panel ────────────────────────────
    net_t = Table(
        box=None, show_header=False,
        expand=True, padding=(0, 1)
    )
    net_t.add_column(width=14)
    net_t.add_column()

    send_spd = stats.get('net_send_speed', 0)
    recv_spd = stats.get('net_recv_speed', 0)
    net_spark = make_sparkline(
        NET_SPEED_HISTORY,
        max_val=max(
            max(NET_SPEED_HISTORY, default=1),
            1
        )
    )

    net_t.add_row(
        "[bold]↑ Upload[/]",
        f"[cyan]{send_spd:.1f} KB/s[/]"
    )
    net_t.add_row(
        "[bold]↓ Download[/]",
        f"[cyan]{recv_spd:.1f} KB/s[/]"
    )
    net_t.add_row(
        "[bold]Total Sent[/]",
        f"[dim]{stats.get('net_sent_total', 0):.1f}"
        f" MB[/]"
    )
    net_t.add_row(
        "[bold]Total Recv[/]",
        f"[dim]{stats.get('net_recv_total', 0):.1f}"
        f" MB[/]"
    )
    net_t.add_row(
        "[bold]Connections[/]",
        f"[yellow]"
        f"{stats.get('net_connections', 0)}[/]"
    )
    net_t.add_row(
        "[bold]Net History[/]",
        f"[magenta]{net_spark}[/]"
    )
    net_t.add_row("", "")
    net_t.add_row(
        "[bold]Disk[/]",
        f"[cyan]"
        f"{stats.get('disk_percent', 0):.1f}% "
        f"({stats.get('disk_used', 0):.1f}/"
        f"{stats.get('disk_total', 0):.1f} GB)[/]"
    )
    disk_bar = make_bar(
        stats.get('disk_percent', 0),
        width=20
    )
    net_t.add_row("", disk_bar)
    net_t.add_row("", "")
    net_t.add_row(
        "[bold]Scanner CPU[/]",
        f"[magenta]"
        f"{stats.get('proc_cpu', 0):.1f}%[/]"
    )
    net_t.add_row(
        "[bold]Scanner RAM[/]",
        f"[magenta]"
        f"{stats.get('proc_mem', 0):.1f} MB[/]"
    )

    net_panel = Panel(
        net_t,
        title="[bold yellow]🌐 NETWORK & DISK[/]",
        border_style="yellow",
        padding=(0, 1)
    )

    # ── Log Panel ────────────────────────────────
    log_text = Text()
    log_colors = {
        '[✓]': 'green',
        '[!]': 'red bold',
        '[*]': 'cyan',
        '[⚠]': 'yellow',
        'ERROR': 'red bold',
        'FOUND': 'red bold',
        'CRITICAL': 'red bold',
        'HIGH': 'red',
        'MEDIUM': 'yellow',
        'COMPLETE': 'green bold',
        'complete': 'green',
        'Started': 'cyan bold',
        '══': 'cyan bold',
    }

    recent_logs = logs[-20:]
    if not recent_logs:
        log_text.append(
            "  Waiting for scanner logs...\n",
            style="dim"
        )
    else:
        for log in recent_logs:
            log = log.strip()
            if not log:
                continue

            color = 'white'
            for keyword, col in log_colors.items():
                if keyword in log:
                    color = col
                    break

            log_text.append(
                f"  {log}\n", style=color
            )

    log_panel = Panel(
        log_text,
        title="[bold magenta]📋 LIVE SCANNER LOGS[/]",
        border_style="magenta",
        padding=(0, 0)
    )

    # ── Status Bar ───────────────────────────────
    status_parts = []

    cpu_pct = stats.get('cpu_percent', 0)
    if cpu_pct < 50:
        status_parts.append(
            "[green]● CPU: Normal[/]"
        )
    elif cpu_pct < 80:
        status_parts.append(
            "[yellow]● CPU: High[/]"
        )
    else:
        status_parts.append(
            "[red]● CPU: Critical![/]"
        )

    mem_pct = stats.get('mem_percent', 0)
    if mem_pct < 70:
        status_parts.append(
            "[green]● RAM: OK[/]"
        )
    elif mem_pct < 90:
        status_parts.append(
            "[yellow]● RAM: High[/]"
        )
    else:
        status_parts.append(
            "[red]● RAM: Critical![/]"
        )

    status_parts.append(
        f"[cyan]↑{send_spd:.0f} "
        f"↓{recv_spd:.0f} KB/s[/]"
    )
    status_parts.append(
        f"[dim]{stats.get('net_connections', 0)}"
        f" conns[/]"
    )
    status_parts.append(
        "[dim]Ctrl+C to exit[/]"
    )

    status_bar = Panel(
        " │ ".join(status_parts),
        style="on grey11",
        height=3
    )

    # ── Assemble Layout ──────────────────────────
    layout = Layout()

    layout.split_column(
        Layout(
            Panel(header, box=box.HEAVY),
            name="header",
            size=3
        ),
        Layout(name="top", size=18),
        Layout(name="logs"),
        Layout(
            status_bar,
            name="status",
            size=3
        )
    )

    layout["top"].split_row(
        Layout(cpu_panel, name="cpu"),
        Layout(mem_panel, name="mem"),
        Layout(net_panel, name="net"),
    )

    layout["logs"].update(log_panel)

    return layout


# ════════════════════════════════════════════════════
#  MAIN MONITOR LOOP
# ════════════════════════════════════════════════════
def run_monitor():
    """Main monitor loop"""
    console.clear()
    console.print(
        "\n[bold cyan]Starting Live Monitor...[/]"
    )
    console.print(
        "[dim]Real-time system stats + "
        "scanner logs[/]\n"
    )

    # Start background stats collector
    collector = StatsCollector()
    time.sleep(1)

    try:
        with Live(
            console=console,
            refresh_per_second=2,
            screen=True
        ) as live:
            while True:
                try:
                    stats = collector.get()
                    logs = read_logs()
                    layout = build_layout(
                        stats, logs
                    )
                    live.update(layout)
                    time.sleep(0.5)

                except KeyboardInterrupt:
                    break
                except Exception:
                    time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()

    console.clear()
    console.print(
        "\n[bold cyan]Monitor closed.[/]"
    )


if __name__ == "__main__":
    run_monitor()
