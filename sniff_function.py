


def snif_ip(interface,count=20):
	
	print("------------- Sniff --------------------")
	
	for i in range(0,len( interface)):
	
		print(str(i) + "." +  interface[i])
	
	choose = (int(input("choose the network interface")))
	
	print(sniff(iface=interface[choose], prn=lambda x: x.summary(),count=40))

	print("---------------------------------------\n")



