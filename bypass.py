import nmap
import sys
import subprocess
import socket
import fcntl
import struct
import optparse
from termcolor import colored, cprint

nm = nmap.PortScanner()
interfaceNo=""
bold=True

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
targetIP=options.ipRange

cmd='ping6 -I '+interfaceNo+' -c 2 ff02::1'
	
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
for x in ipv4List:
	#cmd="/usr/sbin/arp -a "+x
	cmd="arp -a "+x
	tmpResults=runCommand(cmd)
	tmpMacAddr=tmpResults.split(" at ")
	if "no match found" not in str(tmpMacAddr):
		tmpMacAddr=tmpMacAddr[1]
		tmpMacAddr=tmpMacAddr.split(" [ether] ")[0]	
		tmpIPv4List.append([x,str(tmpMacAddr)])
		print x+"\t"+str(tmpMacAddr)

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
			

