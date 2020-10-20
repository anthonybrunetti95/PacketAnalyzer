


def snif_ip(interface,count=20):
	
	print("------------- Sniff --------------------")
	
	for i in range(0,len( interface)):
	
		print(str(i) + "." +  interface[i])
	
	choose = (int(input("choose the network interface")))
	
	print(sniff(iface=interface[choose], prn=lambda x: x.summary(),count=40))

	print("---------------------------------------\n")



conf.use_pcap = True

send(IP(dst="192.168.178.1", ihl=2, version=3)/ICMP())

a = sniff(filter="icmp ", count=2)

a.nsummary()

a[1]


pkts = sniff(filter="arp",prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"), count=2)


ans,unans = sniff(filter="tcp",prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
ans.nsummary()


ans,unans = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n} {Raw:%Raw.load%\n}"))

res, unans = traceroute(["192.168.178.1"],dport=[80,443],maxttl=20,retry=-2)
