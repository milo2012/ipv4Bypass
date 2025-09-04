#!/usr/bin/env python3
import os
import nmap
import sys
import subprocess
import socket
import fcntl
import struct
import optparse
import re
import shutil
import shlex

# --- discover arp-scan dynamically ---
arpscanToolPath = shutil.which("arp-scan") or "/usr/sbin/arp-scan"
if not os.path.exists(arpscanToolPath):
    print("[-] arp-scan not found (not in PATH and not at /usr/sbin/arp-scan)")
    sys.exit()
else:
    print("[*] Using arp-scan at:", arpscanToolPath)

nm = nmap.PortScanner()
interfaceNo = ""
bold = True

# --- ANSI color replacement ---
def setColor(message, bold=False, color=None, onColor=None):
    """
    Return a string wrapped in ANSI escape codes for color and bold.
    color/onColor options: black, red, green, yellow, blue, magenta, cyan, white
    """
    colors = {
        "black": 30, "red": 31, "green": 32, "yellow": 33,
        "blue": 34, "magenta": 35, "cyan": 36, "white": 37
    }
    onColors = {
        "on_black": 40, "on_red": 41, "on_green": 42, "on_yellow": 43,
        "on_blue": 44, "on_magenta": 45, "on_cyan": 46, "on_white": 47
    }

    seq = ""
    if bold:
        seq += "\033[1m"
    if color and color in colors:
        seq += f"\033[{colors[color]}m"
    if onColor and onColor in onColors:
        seq += f"\033[{onColors[onColor]}m"

    reset = "\033[0m"
    return f"{seq}{message}{reset}"

# --- Utility Functions ---
def mac_to_ipv6_linklocal(mac):
    edit_mac_format = mac.replace('b','').replace("'",'').replace(' ','').replace('.','').replace(':','').replace('-','')
    mac_value = int(edit_mac_format, 16)
    high2 = mac_value >> 32 & 0xffff ^ 0x0200
    high1 = mac_value >> 24 & 0xff
    low1 = mac_value >> 16 & 0xff
    low2 = mac_value & 0xffff
    return 'fe80::{:04x}:{:02x}ff:fe{:02x}:{:04x}'.format(high2, high1, low1, low2)

def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

def dec2bin(n,d=None):
    s = ""
    while n>0:
        s = ("1" if n&1 else "0") + s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    return s if s != "" else "0"

def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def convertCIDR(c):
    tmpResultList=[]
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        tmpResultList.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            tmpResultList.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return tmpResultList

def validateCIDRBlock(b):
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        return False
    prefix, subnet = b.split("/")
    quads = prefix.split(".")
    for q in quads:
        if int(q) < 0 or int(q) > 255:
            print("Error: quad "+str(q)+" wrong size.")
            return False
    if int(subnet) < 1 or int(subnet) > 32:
        print("Error: subnet "+str(subnet)+" wrong size.")
        return False
    return True

def diff(li1, li2):
    return list(set(li1) - set(li2))

def get_hw_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    return ''.join(['%02x:' % b for b in info[18:24]])[:-1]

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(ifname[:15], 'utf-8')))[20:24])

def get_ip_addressv6(ifname):
    try:
        p1 = subprocess.Popen(["ifconfig", ifname], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(["grep", "-i", "inet6"], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p3 = subprocess.Popen(["awk","{print $2}"], stdin=p2.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        stdout, stderr = p3.communicate()
        out_str = stdout.decode('utf-8', errors='ignore').strip()
        for line in out_str.splitlines():
            if line.strip(): return line.strip()
    except Exception:
        return ""
    return ""

def ipv62mac(ipv6):
    if isinstance(ipv6, bytes):
        ipv6 = ipv6.decode('utf8', errors='ignore')
    ipv6 = ipv6.split("%")[0]
    if "/" in ipv6: ipv6 = ipv6.split("/")[0]
    ipv6Parts = ipv6.split(":")
    macParts = []
    for ipv6Part in ipv6Parts[-4:]:
        while len(ipv6Part) < 4: ipv6Part = "0" + ipv6Part
        macParts.append(ipv6Part[:2])
        macParts.append(ipv6Part[-2:])
    macParts[0] = "%02x" % (int(macParts[0],16)^2)
    del macParts[4]; del macParts[3]
    return ":".join(macParts)

def runCommand(cmd):
    try: cmdList = shlex.split(cmd)
    except Exception: cmdList = cmd.split(" ")
    out = subprocess.Popen(cmdList, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    return stdout

def getRemoteMac(ip):
    tmpMacAddr = ""
    target = ip.decode() if isinstance(ip, bytes) else str(ip)
    try:
        a = nm.scan(hosts=target, arguments='-sP -6')
    except Exception:
        return tmpMacAddr
    scan_dict = a.get('scan', {}) if isinstance(a, dict) else {}
    for k,v in scan_dict.items():
        vendor = v.get('vendor','') if isinstance(v, dict) else v.get('vendor','')
        x = str(vendor).split("': '")[0].replace("{'","")
        return x
    return tmpMacAddr

def scanTarget(ipv4, ipv6):
    tmpIPv4pPortList=[]; tmpIPv6pPortList=[]
    try:
        nm.scan(hosts=ipv6, arguments='-sT -6 -T4 --top-ports 65535')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                tmpIPv6pPortList += list(nm[host][proto].keys())
    except Exception: pass
    try:
        nm.scan(hosts=ipv4, arguments='-sT -T4 --top-ports 65535')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                tmpIPv4pPortList += list(nm[host][proto].keys())
    except Exception: pass
    return tmpIPv4pPortList, tmpIPv6pPortList

# --- Command line parsing ---
parser = optparse.OptionParser()
parser.add_option('-i', action="store", dest="interfaceNo", help="Network interface (e.g. eth0)")
parser.add_option('-r', action="store", dest="ipRange", help="Local network IP range (e.g. 192.168.0.1/24)")
options, remainder = parser.parse_args()
if not options.interfaceNo or not options.ipRange:
    print("[*] Please provide the -i and -r options")
    sys.exit()

interfaceNo = options.interfaceNo
myMac = get_hw_address(interfaceNo)
myIP = get_ip_address(interfaceNo)
myIPv6 = get_ip_addressv6(interfaceNo)
targetIP = (options.ipRange).strip()
if not validateCIDRBlock(targetIP):
    sys.exit()

convertedIPv6LinkLocalList=[]
ipv6List=[]

# --- ping IPv6 all-nodes multicast ---
if myIPv6 and myIPv6.startswith("2620:"):
    cmd = f"ping6 -I {myIPv6} -c 2 ff02::1%{interfaceNo}"
else:
    cmd = f"ping6 -c 2 ff02::1%{interfaceNo}"

stdout = runCommand(cmd).decode('utf-8', errors='ignore')
for line in stdout.splitlines():
    if " bytes from " in line:
        tmpIP = line.split()[3].rstrip(':')
        if tmpIP not in ipv6List and len(tmpIP)>0:
            ipv6List.append(tmpIP)

# --- discover IPv4 hosts ---
nm.scan(targetIP, arguments='-sP -T4')
ipv4List=[]
for x in nm.all_hosts(): ipv4List.append(x)

# --- arp-scan ---
tmpIPTargetList = convertCIDR(targetIP)
cmd = f"{arpscanToolPath} -I {interfaceNo} {targetIP}"
tmpResults_str = runCommand(cmd).decode('utf-8', errors='ignore')
tmpIPv4List=[]
for line in tmpResults_str.splitlines():
    for y in tmpIPTargetList:
        if y + "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 2:
                tmpIPv4List.append([parts[0].strip(), parts[1].strip()])
                print(parts[0].strip() + "\t" + parts[1].strip())

# --- convert MAC to IPv6 ---
print("\n[*] Converting Mac Address to Link Local IPv6 addresses")
for x in tmpIPv4List:
    tmpLocalIPv6 = mac_to_ipv6_linklocal(x[1])
    print(tmpLocalIPv6 + "\t" + x[1].upper() + "\t" + x[0])
    convertedIPv6LinkLocalList.append([tmpLocalIPv6, x[1].upper(), x[0]])

# --- match IPv4 and IPv6 hosts ---
tmpCompletedMacAddrList=[]; tmpResultList=[]
print("\n[*] Matching IPv4 and IPv6 addresses")
for y in ipv6List:
    tmpMacAddr = getRemoteMac(y) or ipv62mac(y)
    for x in tmpIPv4List:
        if tmpMacAddr.lower() == x[1].lower():
            tmpResultList.append([y, tmpMacAddr, x[0]])
            tmpCompletedMacAddrList.append(tmpMacAddr)
            print(y + "\t" + tmpMacAddr + "\t" + x[0])

# --- compare ports ---
print("\n[*] Comparing ports on IPv4 and IPv6 interfaces on hosts")
for x in tmpResultList:
    if x[2] != myIP:
        tmpIPv4pPortList, tmpIPv6pPortList = scanTarget(x[2], str(x[0]))
        diffPorts = diff(tmpIPv6pPortList, tmpIPv4pPortList)
        if diffPorts:
            print(x[2] + "\t[" + x[0] + "] - Additional ports on IPv6: " + setColor(", ".join(map(str,diffPorts)), bold, color="red"))
