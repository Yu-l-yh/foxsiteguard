"""
FoxSiteGuard Launcher - starts backend server and opens browser.
Run: python -m foxsiteguard.launcher
"""
import sys, os, subprocess, time, webbrowser, urllib.request

HOST = "127.0.0.1"
PORT = 8000
HEALTH_URL = f"http://{HOST}:{PORT}/health"

def print_banner():
    print()
    print("  ========================================")
    print("       FoxSiteGuard v2.0.0")
    print("       Anti-Phishing Protection")
    print("  ========================================")
    print()

def wait_for_server(url, timeout=15):
    for i in range(timeout):
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                return resp.status == 200
        except Exception:
            time.sleep(1)
    return False

def main():
    print_banner()
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    print(f"  Starting server: http://{HOST}:{PORT}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "foxsiteguard.core.api:app",
         "--host", HOST, "--port", str(PORT), "--log-level", "warning"],
        cwd=project_dir,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    print("  Waiting for server...")
    if not wait_for_server(HEALTH_URL):
        print("  ERROR: Server failed to start.")
        proc.terminate()
        sys.exit(1)

    print("  [OK] Server is running!")
    print()
    print("  Extension setup:")
    print("    chrome://extensions -> Dev mode -> Load unpacked")
    print(f"    Select: {os.path.join(project_dir, 'foxsiteguard', 'chrome-extension')}")
    print()
    print("  Opening browser...")
    webbrowser.open(f"http://{HOST}:{PORT}/docs")
    time.sleep(1)
    webbrowser.open("chrome://extensions")
    print()
    print("  Press Ctrl+C to stop server.")
    print()

    try:
        for line in proc.stdout:
            pass
    except KeyboardInterrupt:
        print("  Shutting down...")
    finally:
        proc.terminate()
        proc.wait()
        print("  Stopped.")

if __name__ == "__main__":
    main()
