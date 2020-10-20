import os
from scapy.all import *
from collections import Counter
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

	choose_protocol = (int(input(" 0. all protocol \n 1. tcp \n 2. udp \n 3. icmp\n")))
	
	if  choose_protocol ==1 :
		result = sniff(iface=interface[choose],count=count)
	else:
		result = sniff(iface=interface[choose],filter=protocol[choose_protocol],
			count=count)
	

	print(result.show())	
	
	more_information = input("visual more information on packet: (y/n) ")
	
	logging.getLogger(result)

	if more_information == "y":
	
		for row in result:
	
			print(row.show())
	
	print( "-----------------------------------------------\n")


def randomIP():

	ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))

	return ip

def randInt():

	x = random.randint(1000,9000)

	return x	

def attack_syn_flood(IP,number):

	for x in range (0,number):
	
		s_port = randInt()
	
		s_eq = randInt()
	
		w_indow = randInt()

		ans,unans = srloop(IP(src = randomIP(),dst=IP)/TCP(sport=s_port ,dport=dstPort,seq = s_eq, window = w_indow, flags="S"),count=number)
	

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
	
	


def dection_syn_flood():

	count =Counter()
	
	pkts = sniff(filter = 'tcp', count = 20)
	
	for pkt in  pkts:
		
		if TCP in pkt and pkt[TCP].flags == 'A':  # TCP SYN packet
	
			src = pkt.sprintf('{IP:%IP.src%}{IPv4:%IPv4.src%}')
	
			count[src] = count[src] + 1	
	
			print(src)

			return count




def main():

	interface = os.listdir('/sys/class/net/')

	db_os_fingerprinting=os_fingerprinting_load()

	choose = int(input('choose what action to perform: '))
	
	print("1. sniff interface\n2. \n3. \n4. \n")
	
	if(choose == 1):
	
		print(sniff_interface(interface))

	elif (choose == 2):

		print(dection_syn_flood())

	elif (choose == 3):
	
		print(scan_host_network())
	
	elif (choose == 4):
	
		ip = input("ip insert")	
	
		print(send_ICMP(ip))
	
	elif (choose == 5):
		
		ip = input("ip insert")	

		print(os_fingerprinting(send_ICMP(ip),db_os_fingerprinting))
		
	elif (choose ==6):
	
		print(scan_port_host('192.168.178.1',80,80))

	elif (choose ==7):
		
		print(get_mac('192.168.178.1'))
	
if __name__ == "__main__":
	main()