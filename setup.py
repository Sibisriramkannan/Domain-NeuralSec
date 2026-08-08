"""
setup.py - Cross-platform auto-setup
Run once: python setup.py
"""

import os
import sys
import subprocess
import platform

PLATFORM = platform.system()
IS_WINDOWS = PLATFORM == 'Windows'
IS_LINUX = PLATFORM == 'Linux'
IS_MAC = PLATFORM == 'Darwin'

print("=" * 55)
print("  Security Scanner - Cross-Platform Setup")
print(f"  Platform: {PLATFORM}")
print("=" * 55)

# Python packages
packages = [
    'requests',
    'requests[socks]',
    'colorama',
    'python-dotenv',
    'groq',
    'beautifulsoup4',
    'reportlab',
    'psutil',
    'rich',
    'pysocks',
    'stem',
    'python-whois',
    'dnspython',
]

print("\n[1] Installing Python packages...")
for pkg in packages:
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip',
             'install', pkg, '--quiet'],
            check=True
        )
        print(f"  ✓ {pkg}")
    except:
        print(f"  ✗ {pkg} FAILED")

# System Tor
print("\n[2] Tor setup...")
if IS_LINUX:
    print("  Linux: Installing Tor via apt...")
    try:
        subprocess.run(
            ['sudo', 'apt', 'install', '-y', 'tor'],
            timeout=60
        )
        subprocess.run(
            ['sudo', 'systemctl', 'enable', 'tor']
        )
        subprocess.run(
            ['sudo', 'systemctl', 'start', 'tor']
        )
        print("  ✓ Tor installed + started")
    except:
        print("  ✗ Manual: sudo apt install tor")

elif IS_MAC:
    print("  macOS: Installing via brew...")
    try:
        subprocess.run(['brew', 'install', 'tor'])
        subprocess.run(
            ['brew', 'services', 'start', 'tor']
        )
        print("  ✓ Tor installed")
    except:
        print("  ✗ Manual: brew install tor")

elif IS_WINDOWS:
    print(
        "  Windows: Download Tor Browser from"
        " torproject.org"
    )
    print(
        "  OR: choco install tor"
        " (if Chocolatey installed)"
    )

# Terminal emulator (Linux)
if IS_LINUX:
    print("\n[3] Terminal emulator check...")
    import shutil
    found = None
    for term in ['gnome-terminal', 'xterm',
                 'konsole', 'xfce4-terminal']:
        if shutil.which(term):
            found = term
            break
    if found:
        print(f"  ✓ {found} found")
    else:
        print("  Installing xterm...")
        try:
            subprocess.run(
                ['sudo', 'apt', 'install',
                 '-y', 'xterm'],
                timeout=30
            )
            print("  ✓ xterm installed")
        except:
            print("  ✗ Manual: sudo apt install xterm")

# .env check
print("\n[4] Checking .env...")
env_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '.env'
)
if os.path.exists(env_path):
    with open(env_path) as f:
        content = f.read()
    if 'GROQ_API_KEY' in content:
        print("  ✓ .env with GROQ_API_KEY found")
    else:
        print("  ✗ GROQ_API_KEY missing in .env")
        print("  Add: GROQ_API_KEY=your_key_here")
else:
    print("  Creating .env template...")
    with open(env_path, 'w') as f:
        f.write("GROQ_API_KEY=your_groq_key_here\n")
    print(
        "  ✓ .env created - add your GROQ key!"
    )

# Output dirs
print("\n[5] Creating output dirs...")
base = os.path.dirname(os.path.abspath(__file__))
for d in [
    'output', 'output/category1',
    'output/category2', 'output/category3',
    'tor_portable'
]:
    os.makedirs(os.path.join(base, d), exist_ok=True)
    print(f"  ✓ {d}/")

print("\n" + "=" * 55)
print("  Setup Complete!")
print("=" * 55)
print(f"\n  Run: python{'3' if IS_LINUX else ''} app.py")
print("=" * 55)
