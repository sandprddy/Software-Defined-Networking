#POX and general imports
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import time

"""
Firewall module that detects and prevents intrusion
***It can be used along with other modules***
Requirements: Environment should contain fake IP's(IP's that are not used) to detect suspicious IP's
When a IP scanner tries to scan fake IP in our network, we record the IP address as suspicious
and keep track of those IP's. If a suspicious IP tries to flood the network above threshold limit in specified
amount of time, then it is blacklisted(Firewall rule is added to the switch)

Algorithm in brief:
For each packet do the following:
1)look whether it is ARP request or other IPV4 packet
2)If dst ip is one of the fake ip's, then record the source address 
  a)if src address is not in suspicious list, make a record and start a timer
  b)if src address is in suspicious list, increse the counter
  c)If the counter of a suspicious list exceeds the threshold, blacklist the IP by installing a flow.
  d)Check the entire suspicious list to delete the one's for which timer is exceeded.
  e)Also delete the flow which is injected by other modules for suspicious ip
"""
#log purpose
log = core.getLogger()

# the switch on which this dynamic firewall should be applied
FIREWALL_SWITCH = 1
THRESHOLD = 10
# the IP's that are being used by the switch
used_IP = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
fake_IP = ["10.0.0.5", "10.0.0.6","10.0.0.7", "10.0.0.8","10.0.0.9","10.0.0.10","10.0.0.11","10.0.0.12",\
           "10.0.0.13","10.0.0.14","10.0.0.15","10.0.0.16","10.0.0.17","10.0.0.18","10.0.0.19","10.0.0.20"]


#suspicious IP's that are flodding the network
suspicious_IP_list = {}
suspicious_IP_time = {}



#add a rule to block a suspicious ip(doesn't deal with ARP flows)
def AddRule(event,packet):  
  #installing flow to block IP that is reponsible for flooding
  log.info("Adding rules to blacklist %s",packet.next.srcip)
  msg = of.ofp_flow_mod()
  msg.idle_timeout = 300
  msg.priority = 30
  msg.match.dl_type = 0x0800
  msg.match.nw_src = packet.next.srcip
  msg.buffer_id = None
  event.connection.send(msg)
  #by default if no action is specified, then the packet is rejected

#add a rule to block a suspicious ip(deals with ARP requests)  
def AddRule_ARP(event,packet):
  #installing flow to block IP that is reponsible for flooding
  log.info("Adding rules to blacklist %s",packet.next.protosrc)
  msg = of.ofp_flow_mod()
  msg.idle_timeout = 300
  msg.priority = 30
  msg.match.dl_type = 0x0806
  msg.match.nw_src = packet.next.protosrc
  msg.buffer_id = None
  event.connection.send(msg)
  #by default if no action is specified, then the packet ss rejected

#Timeout check of suspicious IPs  
def check_timeout(suspicious_IP_list,suspicious_IP_time):
  #check the timer corresponding to each suspicious IP. If timer exceeds threshold, delete it.
  for key in suspicious_IP_time:
    if time.time()-suspicious_IP_time[key] > 1000: #threshold time of 1000 sec..
       #deleting src from suspicious list as the time exceeded the limit
       del suspicious_IP_list[key]
       del suspicious_IP_time[key]

#delete a flow   
def Delrule(packet,event):
  #deleting the flow installed for fake IP's by other modules.
  #log.info("Deleting a flow corresponding to a fake IP")
  msg = of.ofp_flow_mod()
  msg.match = of.ofp_match.from_packet(packet, event.port)
  msg.idle_timeout = 10
  msg.hard_timeout = 30
  msg.command = of.OFPFC_DELETE
  event.connection.send(msg)

def _handle_PacketIn (event):
  
  global FIREWALL_SWITCH
  global used_IP
  global used_PORT
  global suspicious_src_list
  global THRESHOLD
  global suspicious_IP_time
  packet = event.parsed
  #install firewall rules only on the a particular switch
  if event.connection.dpid != FIREWALL_SWITCH:
    return
  
  #check whether ARP
  if isinstance(packet.next, arp):
    #ignore if the packet is originated from our own source ip's(internal)
    if packet.next.protosrc in used_IP or packet.next.protosrc in fake_IP:
      return
    if not packet.next.protodst in used_IP:
      if not packet.next.protosrc in suspicious_IP_list: 
        suspicious_IP_list[packet.next.protosrc] = 1
        log.info("A suspicious source %s is trying to attack. Monitoring it's activity", packet.next.protosrc)
        suspicious_IP_time[packet.next.protosrc] = time.time()
      else:
        suspicious_IP_list[packet.next.protosrc] = suspicious_IP_list[packet.next.protosrc]+1
        if suspicious_IP_list[packet.next.protosrc] > THRESHOLD:
          AddRule_ARP(event,packet)
          del suspicious_IP_list[packet.next.protosrc]
          del suspicious_IP_time[packet.next.protosrc]
          check_timeout(suspicious_IP_list,suspicious_IP_time)
      Delrule(packet,event)		  

  #checking whether l3
  if isinstance(packet.next, ipv4):
    #ignore if the packet is originated from our own source ip's(internal)
    if packet.next.srcip in used_IP or packet.next.srcip in fake_IP:
      return
    #log.info("IP Packet %s ===> %s", packet.next.srcip,packet.next.dstip)
    if not packet.next.dstip in used_IP:
      if not packet.next.srcip in suspicious_IP_list:
        suspicious_IP_list[packet.next.srcip] = 1
        log.info("A suspicious source %s is trying to attack. Monitoring it's activity", packet.next.srcip)
        suspicious_IP_time[packet.next.srcip] = time.time()
      else:
        suspicious_IP_list[packet.next.srcip] = suspicious_IP_list[packet.next.srcip]+1
        #log.info("Increased the counter for %s",packet.next.srcip)		
        if suspicious_IP_list[packet.next.srcip] > THRESHOLD :
          AddRule(event,packet)
          #deleting IP from suspicious list
          del suspicious_IP_list[packet.next.srcip]
          del suspicious_IP_time[packet.next.srcip]
          #also check if the timeout has exceeded for a particular ip. If so delete it from suspicious list
          check_timeout(suspicious_IP_list,suspicious_IP_time)
      #l2_learning must have installed a flow for forwarding to fake IP. Delete those flows
      Delrule(packet,event)	  

  

#main function that starts the module
def launch ():
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
