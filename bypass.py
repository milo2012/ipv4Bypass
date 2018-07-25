#!/usr/bin/env python 
import nmap
import sys
import subprocess
import socket
import fcntl
import struct
import optparse

import re
from termcolor import colored, cprint

nm = nmap.PortScanner()
interfaceNo=""
bold=True

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
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

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
        x=bin2ip(baseIP)
        tmpResultList.append(x)
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            x=bin2ip(ipPrefix+dec2bin(i, (32-subnet)))
            tmpResultList.append(x)
    return tmpResultList
            
def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):

        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        print "Error: subnet "+str(subnet)+" wrong size."
        return False
    # passed all checks -> return True
    return True
    
def diff(li1, li2):
    return (list(set(li1) - set(li2)))

def setColor(message, bold=False, color=None, onColor=None):
	retVal = colored(message, color=color, on_color=onColor, attrs=("bold",))
	return retVal

def get_hw_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_ip_addressv6(ifname):
    cmd = "ifconfig "+ifname
    p1 = subprocess.Popen(["ifconfig",ifname],stdout=subprocess.PIPE)

    cmd = "grep -i inet6"
    p2 = subprocess.Popen(["grep","-i","inet6"],stdin=p1.stdout,stdout=subprocess.PIPE)
	
    cmd = "awk '{print $2}'"
    p3 = subprocess.Popen(["awk","{print $2}"],stdin=p2.stdout,stdout=subprocess.PIPE)
    stdout,stderr = p3.communicate()
    return (stdout).strip()

def ipv62mac(ipv6):
    ipv6=ipv6.split("%")[0]
    # remove subnet info if given
    subnetIndex = ipv6.find("/")
    if subnetIndex != -1:
        ipv6 = ipv6[:subnetIndex]

    ipv6Parts = ipv6.split(":")
    macParts = []
    for ipv6Part in ipv6Parts[-4:]:
        while len(ipv6Part) < 4:
            ipv6Part = "0" + ipv6Part
        macParts.append(ipv6Part[:2])
        macParts.append(ipv6Part[-2:])

    # modify parts to match MAC value
    macParts[0] = "%02x" % (int(macParts[0], 16) ^ 2)
    del macParts[4]
    del macParts[3]

    return ":".join(macParts)

def runCommand(cmd):
	cmdList=cmd.split(" ")
	out = subprocess.Popen(cmdList,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
	stdout,stderr = out.communicate()
	return stdout

def getRemoteMac(ip):
	tmpMacAddr=""
	a=nm.scan(hosts=ip, arguments='-sP -6') 
	for k,v in a['scan'].iteritems(): 
		x=str(v['vendor']).split("': '")[0]
		x=x.replace("{'","")
		return x
def scanTarget(ipv4,ipv6):
	tmpIPv4pPortList=[]
	tmpIPv6pPortList=[]
        a=nm.scan(hosts=ipv6, arguments='-sT -6 -T4 --top-ports 65535') 
	for host in nm.all_hosts():
		for proto in nm[host].all_protocols():
			lport = nm[host][proto].keys()
			for port in lport:	
				tmpIPv6pPortList.append(port)
        a=nm.scan(hosts=ipv4, arguments='-sT -T4 --top-ports 65535') 
	for host in nm.all_hosts():
		for proto in nm[host].all_protocols():
			lport = nm[host][proto].keys()
			for port in lport:	
				tmpIPv4pPortList.append(port)
	return tmpIPv4pPortList,tmpIPv6pPortList

parser = optparse.OptionParser()
parser.add_option('-i', action="store", dest="interfaceNo", help="Network interface (e.g. eth0)")
parser.add_option('-r', action="store", dest="ipRange", help="Local network IP range (e.g. 192.168.0.1/24)")
options, remainder = parser.parse_args()
if not options.interfaceNo or not options.ipRange:
	print "[*] Please provide the -i and -r options"
	sys.exit()

interfaceNo=options.interfaceNo
myMac=get_hw_address(interfaceNo)
myIP=get_ip_address(interfaceNo)
myIPv6=get_ip_addressv6(interfaceNo)
targetIP=(options.ipRange).strip()
if not validateCIDRBlock(targetIP):
	sys.exit()
	
cmd=""
if myIPv6.startswith("2620:"):
	cmd='ping6 -I '+myIPv6+' -c 2 ff02::1%'+interfaceNo
else:
	cmd='ping6 -c 2 ff02::1%'+interfaceNo
	
cmdList=cmd.split(" ")
out = subprocess.Popen(cmdList,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
ipv6List=[]
stdout,stderr = out.communicate()
tmpResultList=stdout.split("\n")
for x in tmpResultList:
	if " bytes from " in x:
		tmpIP=x.split(" ")[3]
		if tmpIP not in ipv6List:
			ipv6List.append(tmpIP)

nm.scan(targetIP,arguments='-sP -T4')
ipv4List=[]
for x in nm.all_hosts():
	if x not in ipv4List:
		ipv4List.append(x)

print "\n[*] Found the below IPv4 addresses"
tmpIPv4List=[]
tmpIPTargetList=convertCIDR(targetIP)

cmd="arp-scan "+targetIP
tmpResults=runCommand(cmd)
tmpList1=tmpResults.split("\n")
for x in tmpList1:
	for y in tmpIPTargetList:
		if y+"\t" in x:
			tmpIP=x.split("\t")[0]
			tmpMacAddr=x.split("\t")[1]
			print tmpIP+"\t"+str(tmpMacAddr)
			tmpIPv4List.append([tmpIP,str(tmpMacAddr)])

print "\n[*] Found the below IPv6 addresses"
tmpIPv6List=[]
for x in ipv6List:
	tmpMacAddr=getRemoteMac(x)
	if tmpMacAddr!="{}":
		tmpIPv6List.append([x,tmpMacAddr])
		print x+"\t"+tmpMacAddr
	else:
		tmpMacAddr=ipv62mac(x)
		tmpIPv6List.append([x,tmpMacAddr])
		if tmpMacAddr==myMac:
			print x+"\t"+tmpMacAddr+" [This Computer]"
		else:
			print x+"\t"+tmpMacAddr
print "\n[*] Matching IPv4 and IPv6 addresses"
tmpResultList=[]
for y in tmpIPv6List:
	tmpFound=False
	for x in tmpIPv4List:
			if y[1].lower()==x[1].lower():
				print y[0]+"\t"+y[1]+"\t"+x[0]
				tmpResultList.append([y[0],y[1],x[0]])
				tmpFound=True
	if tmpFound==False:
		if [y[0],"",""] not in tmpResultList:
			tmpMac=ipv62mac(y[0])
			if tmpMac==myMac:
				print y[0]+"\t"+tmpMac+"\t"+myIP+" [This Computer]"
				tmpResultList.append([y[0],tmpMac,myIP])
				#tmpResultList.append([y[0],tmpMac,"[This Computer]"])
			else:
				print y[0]+"\t"+tmpMac
				tmpResultList.append([y[0],tmpMac,""])

print "\n[*] Comparing ports on IPv4 and IPv6 interfaces on hosts"
for x in tmpResultList:
	if x[2]!=myIP:
		#if x[2]!="[This Computer]":
		tmpIPv4pPortList,tmpIPv6pPortList=scanTarget(x[2],x[0])
		if len(tmpIPv4pPortList)!=len(tmpIPv6pPortList):
			if len(tmpIPv6pPortList)>len(tmpIPv4pPortList):
				if len(x[2])>0:
					diffList=diff(tmpIPv6pPortList,tmpIPv4pPortList)
					tmpResultList=[]
					for y in diffList:
						if y in tmpIPv6pPortList:
							tmpResultList.append(str(y))
					if len(tmpResultList)>0:
						print x[2]+"\t["+x[0]+"] - Additional ports on IPv6: "+setColor(", ".join(tmpResultList), bold, color="red")
					else:
						print x[2]+"\t["+x[0]+"]"			
				else:	
					#print "["+x[0]+"]"
					diffList=diff(tmpIPv6pPortList,tmpIPv4pPortList)
					tmpResultList=[]
					for y in diffList:
						if y in tmpIPv6pPortList:
							tmpResultList.append(str(y))
					if len(tmpResultList)>0:
						print "["+x[0]+"] - Additional ports on IPv6: "+setColor(", ".join(tmpResultList), bold, color="red")
					else:
						print "["+x[0]+"]"			
			else:
				print x[2]+"\t["+x[0]+"] - No additional ports on IPv6"
			

