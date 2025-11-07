#!/usr/bin/env python3
"""
scanner_no_root.py
Non-root network scanner: TCP-based host discovery, port scan, banner grab, CSV output.

Usage:
    python3 scanner_no_root.py

Edit TARGETS or SUBNET and PORTS below as needed.
Only scan machines you own or have permission to test.
"""
import socket
import csv
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------- CONFIG ----------
# Change these defaults if you want:
TARGETS = []             # example: ["192.168.56.101","192.168.56.102"]
SUBNET = "127.0.0.1/32"  # can be "192.168.56.0/24" or "127.0.0.1/32"
PORTS = [21,22,23,25,53,80,110,139,143,443,445,3389]  # ports to test
CONNECT_TIMEOUT = 1.0
MAX_THREADS = 200
OUTPUT_CSV = "results.csv"
# ----------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Non-root TCP scanner")
    p.add_argument("--targets", "-t", nargs="+", help="List of IPs to scan")
    p.add_argument("--subnet", "-s", help="CIDR subnet to scan (eg. 192.168.56.0/24)")
    p.add_argument("--ports", "-p", help="Comma-separated ports (eg. 22,80,443)")
    p.add_argument("--outfile", "-o", help="CSV output filename", default=OUTPUT_CSV)
    return p.parse_args()

def expand_targets(target_list, subnet_cidr):
    ips = set()
    if target_list:
        for t in target_list:
            try:
                ips.add(str(ipaddress.ip_address(t)))
            except Exception:
                # maybe user passed a hostname
                ips.add(t)
    if subnet_cidr:
        try:
            net = ipaddress.ip_network(subnet_cidr, strict=False)
            for ip in net.hosts():
                ips.add(str(ip))
        except Exception as e:
            print(f"[!] Invalid subnet '{subnet_cidr}': {e}")
    return sorted(ips)

def is_host_up_tcp(ip, probe_ports=(80,443), timeout=CONNECT_TIMEOUT):
    # Try connecting to common service ports to consider host "alive"
    for p in probe_ports:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            err = s.connect_ex((ip, p))
            s.close()
            if err == 0:
                return True
        except Exception:
            continue
    # fallback: try a single short TCP connect to port 1..1024? avoid scanning whole range here
    return False

def grab_banner(ip, port, timeout=CONNECT_TIMEOUT):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        # send small probes for HTTP/SMTP where appropriate
        try:
            if port in (80, 8080):
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 25:
                s.sendall(b"HELO example\r\n")
        except Exception:
            pass
        try:
            data = s.recv(1024)
            return data.decode(errors="ignore").strip()
        except Exception:
            return ""
        finally:
            s.close()
    except Exception:
        return ""

def scan_port(ip, port, timeout=CONNECT_TIMEOUT):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        err = s.connect_ex((ip, port))
        s.close()
        if err == 0:
            banner = grab_banner(ip, port, timeout=timeout)
            return (ip, port, "open", banner)
        else:
            return None
    except Exception:
        return None

def scan_host_ports(ip, ports, max_workers=100):
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
    return results

def main():
    args = parse_args()

    targets = expand_targets(args.targets or TARGETS, args.subnet or SUBNET)
    if args.ports:
        ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    else:
        ports = PORTS

    if not targets:
        print("[!] No targets found. Set --targets or --subnet or edit defaults in the script.")
        return

    print(f"Scan started: {len(targets)} target(s), {len(ports)} port(s) each")
    print("Time:", datetime.now().isoformat())

    alive_hosts = []
    print("\n[+] Host discovery (TCP probe)...")
    with ThreadPoolExecutor(max_workers=min(200, len(targets) or 1)) as ex:
        future_map = {ex.submit(is_host_up_tcp, ip): ip for ip in targets}
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                up = fut.result()
            except Exception:
                up = False
            print(f"  {ip} -> {'up' if up else 'unknown/down'}")
            if up:
                alive_hosts.append(ip)

    # If no hosts detected as up, optionally try scanning all targets anyway:
    if not alive_hosts:
        print("[!] No hosts responded to probes. Continuing to scan all targets anyway.")
        alive_hosts = targets

    all_results = []
    print("\n[+] Scanning ports (this may take a little while)...")
    for host in alive_hosts:
        print(f"Scanning {host} ...")
        res = scan_host_ports(host, ports, max_workers=200)
        for r in res:
            print(f"  {host}:{r[1]} -> {r[2]}")
        all_results.extend(res)

    # Write CSV
    outfile = args.outfile
    print(f"\nWriting results to {outfile}")
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "port", "state", "banner"])
        for row in all_results:
            writer.writerow(row)

    print("Scan finished. Summary:")
    if all_results:
        for r in all_results:
            print(f" {r[0]}:{r[1]} {r[2]} {('-- ' + r[3]) if r[3] else ''}")
    else:
        print(" No open ports found (with the scanned ports).")
    print("Done.")

if __name__ == "__main__":
	main()
