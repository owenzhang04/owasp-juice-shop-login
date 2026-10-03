#!/usr/bin/env python3
import subprocess
import time
import os

chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
base_dir = os.path.abspath(".")
html_file = os.path.join(base_dir, "generate_pdf.html")
pdf_out = os.path.join(base_dir, "HW2B_OWASP_Juice_Shop.pdf")

cmd = [
    chrome_bin,
    "--headless=new",
    "--disable-gpu",
    f"--user-data-dir={os.path.join(base_dir, 'scratch_chrome')}",
    f"--print-to-pdf={pdf_out}",
    "--no-pdf-header-footer",
    f"file://{html_file}"
]

print("Compiling PDF...")
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(3.5)
proc.terminate()
try:
    proc.wait(timeout=1)
except:
    proc.kill()

if os.path.exists(pdf_out) and os.path.getsize(pdf_out) > 0:
    print(f"Success! Generated PDF at {pdf_out} ({os.path.getsize(pdf_out)} bytes)")
else:
    print("Failed to generate PDF.")
