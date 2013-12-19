#!/usr/bin/env python
#@rahil sharma
#usage pyhton rsip.py mon1 authorized mac id   ipaddress range
#example our network has some ip address and has one authorized mac_id
#here we track down any access points that are using our network


from scapy import *
import re
import sys, os, signal 
from multiprocessing import Process

from scapy.all import *
interface = sys.argv[1]   
baseMAC = sys.argv[2]  
IPregex = sys.argv[3]
reg=re.compile(IPregex)
#while taking input first we need to compile the function then use search and match function on it
#check for ip layer and extract it first 
#check for ip address source and destination both
#if we find a match then we compare with the list of authorized mac address
#here use all three addresses Dot11.addr1 2 3
#if mac address is not authorized then display the result
def monitorIPMAC(p):       
     if p.haslayer(IP):
          iplayer = p.getlayer(IP)
          if reg.match(iplayer.src) or reg.match(iplayer.dst):
             if not (p.addr1==baseMAC or p.addr2==baseMAC or p.addr3==baseMAC): 
                    print "---"
                    print "MAC->"+p.addr1+"|"+p.addr2+"|"+p.addr3
                    print "IP->"+iplayer.src+"|"+iplayer.dst
                    print "---"       
sniff(iface=interface,prn=monitorIPMAC)

