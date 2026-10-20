#!/usr/bin/env python3
"""
TVOSRecon Companion Listener
Discovers and connects to TVOSRecon running on an Apple TV,
receives reconnaissance data as newline-delimited JSON, and
writes it to a timestamped log file.

Usage:
    python3 listener.py                        # auto-discover via Bonjour
    python3 listener.py --host 192.168.1.50    # manual IP, default port
    python3 listener.py --host 192.168.1.50 --port 9100

Requirements:
    pip install zeroconf
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime

try:
    from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf
except ImportError:
    print("Error: zeroconf library required.  Install with:\n  pip install zeroconf")
    sys.exit(1)

SERVICE_TYPE = "_tvosrecon._tcp.local."
DEFAULT_PORT = 9100

# ANSI color codes
COLORS = {
    "SystemInfo":              "\033[96m",
    "SysctlProbe":             "\033[93m",
    "FileSystemWalker":        "\033[92m",
    "DyldCacheInspector":      "\033[95m",
    "MachInspector":           "\033[91m",
    "IOKitExplorer":           "\033[94m",
    "SandboxProfiler":         "\033[33m",
    "XPCServiceProber":        "\033[36m",
    "NetworkProbe":            "\033[32m",
    "SyscallProber":           "\033[31m",
    "MemoryLayoutMapper":      "\033[35m",
    "EntitlementChecker":      "\033[34m",
    "KeychainProbe":           "\033[96m",
    "HardwareProbe":           "\033[93m",
    "ProcessEnumeration":      "\033[92m",
    "ObjectiveCRuntime":       "\033[95m",
    "MountedFilesystems":      "\033[91m",
    "ResourceLimits":          "\033[94m",
    "POSIXIPCProbe":           "\033[33m",
    "DarwinNotifications":     "\033[36m",
    "NetworkServiceDiscovery": "\033[32m",
    "URLSchemeProber":         "\033[31m",
    "MetalGPUProbe":           "\033[35m",
    "MediaCapabilities":       "\033[34m",
    "CryptoCapabilities":      "\033[96m",
    "MachTrapProbe":           "\033[93m",
    "ClockAndTimers":          "\033[92m",
    "PasteboardAndAppState":   "\033[95m",
    "OSLogProbe":              "\033[91m",
    "ThermalAndPowerProbe":    "\033[94m",
    "DispatchAndGCDProbe":     "\033[33m",
    "AccessibilityAndUIProbe": "\033[36m",
    "CompilerAndRuntimeInfo":  "\033[32m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


class ReconListener:
    def __init__(self, host=None, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.running = True
        self.discovered = threading.Event()
        self.line_count = 0
        self.error_count = 0
        self.current_module = ""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.outfile = f"tvosrecon_{ts}.json"

    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            if info:
                addresses = info.parsed_addresses()
                if addresses:
                    self.host = addresses[0]
                    self.port = info.port
                    print(f"{BOLD}[*] Discovered TVOSRecon at {self.host}:{self.port}{RESET}")
                    self.discovered.set()

    def discover(self):
        print(f"{BOLD}[*] Searching for TVOSRecon via Bonjour (_tvosrecon._tcp) ...{RESET}")
        zc = Zeroconf()
        ServiceBrowser(zc, SERVICE_TYPE, handlers=[self.on_service_state_change])
        while self.running and not self.discovered.wait(timeout=1.0):
            pass
        zc.close()

    def connect_and_receive(self):
        while self.running:
            try:
                print(f"{BOLD}[*] Connecting to {self.host}:{self.port} ...{RESET}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.host, self.port))
                sock.settimeout(None)
                print(f"{BOLD}[+] Connected. Writing to {self.outfile}{RESET}\n")
                self._receive_loop(sock)
            except ConnectionRefusedError:
                print(f"{DIM}[!] Connection refused, retrying in 3s ...{RESET}")
                time.sleep(3)
            except ConnectionResetError:
                print(f"\n{DIM}[!] Connection reset by device.{RESET}")
                break
            except socket.timeout:
                print(f"{DIM}[!] Connection timed out, retrying in 3s ...{RESET}")
                time.sleep(3)
            except OSError as e:
                if self.running:
                    print(f"{DIM}[!] Socket error: {e}, retrying in 3s ...{RESET}")
                    time.sleep(3)
                else:
                    break

    def _receive_loop(self, sock):
        buf = b""
        with open(self.outfile, "a") as fout:
            while self.running:
                try:
                    data = sock.recv(65536)
                    if not data:
                        print(f"\n{DIM}[*] Connection closed by device.{RESET}")
                        break
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        text = line.decode("utf-8", errors="replace").strip()
                        if not text:
                            continue
                        fout.write(text + "\n")
                        fout.flush()
                        self._print_line(text)
                except socket.timeout:
                    continue
                except OSError:
                    break
        sock.close()

    def _print_line(self, text):
        self.line_count += 1
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            print(text)
            return

        module = obj.get("module", "?")
        key    = obj.get("key", "")
        error  = obj.get("error")

        color = COLORS.get(module, "\033[37m")

        if module != self.current_module:
            self.current_module = module
            print(f"\n{BOLD}{color}{'='*60}")
            print(f"  Module: {module}")
            print(f"{'='*60}{RESET}")

        if error:
            self.error_count += 1
            print(f"  {color}[ERR]{RESET} {key}: {DIM}{error}{RESET}")
        else:
            value = obj.get("value", "")
            vstr = str(value)
            if len(vstr) > 200:
                vstr = vstr[:200] + " ..."
            print(f"  {color}[+]{RESET} {key}: {vstr}")

    def stop(self):
        self.running = False
        self.discovered.set()

    def summary(self):
        print(f"\n{BOLD}{'='*60}")
        print(f"  TVOSRecon collection complete")
        print(f"  Lines received : {self.line_count}")
        print(f"  Errors         : {self.error_count}")
        print(f"  Output file    : {os.path.abspath(self.outfile)}")
        print(f"{'='*60}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="TVOSRecon companion listener")
    parser.add_argument("--host", help="Apple TV IP address (skip Bonjour discovery)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port (default {DEFAULT_PORT})")
    args = parser.parse_args()

    listener = ReconListener(host=args.host, port=args.port)

    def handle_sigint(_sig, _frame):
        print(f"\n{BOLD}[*] Interrupted.{RESET}")
        listener.stop()

    signal.signal(signal.SIGINT, handle_sigint)

    if listener.host is None:
        listener.discover()
        if not listener.running:
            return

    if listener.host:
        listener.connect_and_receive()
    listener.summary()


if __name__ == "__main__":
    main()
