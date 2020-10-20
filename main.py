import os
from scapy.all import *
import time
import logging
import matplotlib
import csv


logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)


def print_output(sezion_name,response):
	print( "----------"+ sezion_name +"-----------------")

	print(response)

	print( "-----------------------------------------------")



# sniff all trafic in the network
def sniff_interface(interface,count=20):
	
	print( "-----Sniff packet in the NetworkInterface-------")

	protocol = ["","tcp", "udp","icmp"]

	for i in range(0,len( interface)):
	
		print(str(i) + "." +  interface[i])
	
	choose = (int(input("choose the network interface:	\n")))
	
	print("choose the protocol: \n")

	choose_protocol = (int(input(" 0. all protocol \n 1.tcp \n 2. udp \n 3. icmp\n")))
	
	if  choose_protocol ==1 :
		result =sniff(iface=interface[choose],count=count)
	else:
		result =sniff(iface=interface[choose],filter=protocol[choose_protocol],
			count=count)
	

	print(result.show())	
	
	more_information = input("visual more information on packet: (y/n) ")
	
	if more_information == "y":
	
		for row in result:
	
			print(row.show())
	
	print( "-----------------------------------------------\n")


def os_fingerprinting_load():
	
	results = []
	
	with open("os ttl.csv") as csvfile:
	
		reader = csv.reader(csvfile)
	
		for row in reader: # each row is a list
	
			if 'ICMP' in row[2]:
	
				results.append((row[0] + row[1],int(row[3])))
	
	return results		

def os_fingerprinting(ttl,db_os_fingerprinting):
	
	for row in db_os_fingerprinting:
		
		if row[1]== ttl:

			return 'The Operative System is: '+row[0]


def send_ICMP(ip):

	ans = sr1(IP(dst=ip)/ICMP()/"XXXXXXXXXXX")

	return ans.ttl



# function that return mac adress through ip adress
def get_mac(ip): 
	
	arp_request = ARP(pdst = ip)

	broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")

	arp_request_broadcast = broadcast / arp_request

	answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]

	return answered_list[0][1].hwsrc


# find host in the netwok
def scan_host_network():

	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.178.0/24"),
		timeout=2)
	
	return ans.nsummary()

def scan_udp(host):
	
	ans, unans = sr(IP(dst=host)/UDP(dport=[(1, 65535)]), inter=0.5, retry=10, 
		timeout=1)
	
	ans.nsummary()


def scan_port_host(ip_host,first_port,ultime_port):

	return report_ports(ip_host,(first_port,ultime_port))
	
	

def main():
	interface = os.listdir('/sys/class/net/')
	db_os_fingerprinting=os_fingerprinting_load()
	#while True:
	print(scan_host_network())
		#sniff_interface(interface,40)
	#print(send_ICMP('192.168.178.30'))
	print(os_fingerprinting(send_ICMP('192.168.178.30'),db_os_fingerprinting))
		#print(ls(ARP))
		#scan_port_host('192.168.178.1',80,80)
		#print(get_mac('192.168.178.1'))
	


if __name__ == "__main__":
	main()