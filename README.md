# ipv4Bypass
**Using IPv6 to Bypass Security**   
    
**Dependences (tested on Kali Linux)**  
python2.7  
nmap  
python-nmap (https://pypi.org/project/python-nmap/)  
termcolor (https://pypi.org/project/termcolor/)  
  
**Example on how to run the tool**  
```
$ python bypass.py -i eth0 -r 10.5.192.0/24  

$ python bypass.py  -h
Usage: bypass.py [options]

Options:
  -h, --help      show this help message and exit
  -i INTERFACENO  Network interface (e.g. eth0)
  -r IPRANGE      Local network IP range (e.g. 192.168.0.1/24)
 
```  

**Screenshot of tool**    
![Screenshot of tool](https://milo2012.files.wordpress.com/2018/06/screen-shot-2018-06-23-at-1-47-06-am.png?w=1190&h=950)  
  
**More information**        
See https://milo2012.wordpress.com/2018/06/22/using-ipv6-to-bypass-security-tool/ for an explanation on the technique and how the tool works.
     

