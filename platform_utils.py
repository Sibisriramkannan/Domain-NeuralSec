"""
platform_utils.py
Cross-platform terminal launcher
QTerminal + Windows + Linux + macOS
"""

import os
import sys
import shutil
import subprocess
import threading
import platform

PLATFORM = platform.system()
IS_WINDOWS = PLATFORM == 'Windows'   # ✅ Add this
IS_LINUX   = PLATFORM == 'Linux'     # ✅ Add this
IS_MAC     = PLATFORM == 'Darwin'    # ✅ Add this
PYTHON = sys.executable


def clear_screen():                  # ✅ Add this
    """Cross-platform screen clear."""
    if IS_WINDOWS:
        os.system('cls')
    else:
        os.system('clear')


def _log(writer, msg, level='INFO'):
    if writer:
        try:
            writer(msg, level)
        except:
            pass


def launch_in_terminal(
    script_path,
    title='Terminal',
    args=None,
    cwd=None,
    log_writer=None
):
    args = args or []
    cwd = cwd or os.path.dirname(
        os.path.abspath(script_path)
    )

    if IS_WINDOWS:
        return _win(
            script_path, title, args,
            cwd, log_writer
        )
    elif IS_MAC:
        return _mac(
            script_path, title, args,
            cwd, log_writer
        )
    else:
        return _linux(
            script_path, title, args,
            cwd, log_writer
        )


def _win(script_path, title, args, cwd, lw):
    cmd = [PYTHON, script_path] + args
    try:
        p = subprocess.Popen(
            cmd, cwd=cwd,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        _log(lw, f'{title}: Windows console', 'SUCCESS')
        return p
    except:
        pass
    if shutil.which('wt'):
        try:
            p = subprocess.Popen(
                ['wt', '--title', title] + cmd,
                cwd=cwd
            )
            _log(lw, f'{title}: Windows Terminal', 'SUCCESS')
            return p
        except:
            pass
    try:
        q = ' '.join(f'"{x}"' for x in cmd)
        os.system(f'start "{title}" {q}')
        _log(lw, f'{title}: cmd start', 'SUCCESS')
        return True
    except:
        pass
    return _bg(script_path, args, cwd, lw)


def _mac(script_path, title, args, cwd, lw):
    cmd = [PYTHON, script_path] + args
    cs = ' '.join(f'"{x}"' for x in cmd)
    try:
        s = (
            f'tell application "Terminal" '
            f'to do script "cd \\"{cwd}\\" && {cs}"'
        )
        p = subprocess.Popen(['osascript', '-e', s])
        _log(lw, f'{title}: macOS Terminal', 'SUCCESS')
        return p
    except:
        pass
    return _bg(script_path, args, cwd, lw)


def _linux(script_path, title, args, cwd, lw):
    cmd = [PYTHON, script_path] + args
    cs = ' '.join(f'"{x}"' for x in cmd)

    terminals = [
        ('qterminal',      ['qterminal', '-T', title, '-e'] + cmd),
        ('gnome-terminal', ['gnome-terminal', '--title', title, '--'] + cmd),
        ('konsole',        ['konsole', '--new-tab', '-p', f'tabtitle={title}', '-e'] + cmd),
        ('xfce4-terminal', ['xfce4-terminal', '--title', title, '-e', cs]),
        ('xterm',          ['xterm', '-T', title, '-e', cs]),
        ('lxterminal',     ['lxterminal', '-t', title, '-e', cs]),
        ('kitty',          ['kitty', '--title', title] + cmd),
        ('alacritty',      ['alacritty', '--title', title, '-e'] + cmd),
        ('mate-terminal',  ['mate-terminal', '--title', title, '-e', cs]),
        ('tilix',          ['tilix', '-t', title, '-e', cs]),
        ('terminator',     ['terminator', '-T', title, '-e', cs]),
    ]

    for name, tcmd in terminals:
        if not shutil.which(name):
            continue
        try:
            p = subprocess.Popen(
                tcmd, cwd=cwd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            _log(lw, f'{title}: {name}', 'SUCCESS')
            return p
        except:
            continue

    if shutil.which('tmux'):
        try:
            p = subprocess.Popen(
                ['tmux', 'new-window', '-n', title, cs],
                cwd=cwd
            )
            _log(lw, f'{title}: tmux', 'SUCCESS')
            return p
        except:
            pass

    if shutil.which('screen'):
        try:
            p = subprocess.Popen(
                ['screen', '-dmS', title, 'bash', '-c', cs],
                cwd=cwd
            )
            _log(lw, f'{title}: screen', 'SUCCESS')
            return p
        except:
            pass

    return _bg(script_path, args, cwd, lw)


def _bg(script_path, args, cwd, lw):
    def _run():
        try:
            subprocess.run(
                [PYTHON, script_path] + (args or []),
                cwd=cwd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    _log(
        lw,
        f'No terminal - {os.path.basename(script_path)} in background',
        'WARN'
    )
    return None
