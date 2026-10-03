#!/usr/bin/env python3
import subprocess
import time
import os

targets = [
    ("test_views/2_empty.html", "screenshots/2_client_validation_empty.png", "1000,800"),
    ("test_views/3_sqli.html", "screenshots/3_sqli_attack_attempt.png", "1000,800"),
    ("test_views/4_xss.html", "screenshots/4_xss_attack_attempt.png", "1000,800"),
    ("test_views/5_terminal.html", "screenshots/5_server_defense_logs.png", "1000,750"),
]

chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
base_dir = os.path.abspath(".")

for src, dest, size in targets:
    url = f"file://{os.path.join(base_dir, src)}"
    out_file = os.path.join(base_dir, dest)
    cmd = [
        chrome_bin,
        "--headless=new",
        "--disable-gpu",
        f"--user-data-dir={os.path.join(base_dir, 'scratch_chrome')}",
        f"--screenshot={out_file}",
        f"--window-size={size}",
        url
    ]
    print(f"Capturing {dest}...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2.5)
    proc.terminate()
    try:
        proc.wait(timeout=1)
    except:
        proc.kill()
    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        print(f"  Successfully wrote {dest} ({os.path.getsize(out_file)} bytes)")
    else:
        print(f"  Warning: {dest} not generated")

print("All captures complete!")
