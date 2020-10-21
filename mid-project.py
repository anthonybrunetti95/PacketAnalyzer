import scapy

Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=["192.168.178.25"],ttl=(1,9))/UDP()

send(IP(dst="0.0.0.0")/TCP(dport=8000,flags="S"))
sr1(IP(dst="127.0.0.1")/TCP(dport=8000,flags="S"))


ans,unans = sr1( IP(dst="192.168.178.50")/TCP(dport=80,flags="S") )
ans.summary( lambda(s,r) : r.sprintf("%IP.src% conteasta") )


import matplotlib
sniff(iface="enp3s0", prn=lambda x: x.summary())

sniff(iface="enp3s0", prn=lambda x: x.show())


#icmp
p = sr1(IP(dst="192.168.178.1")/ICMP()/"XXXXXXXXXXX")
p.show()

# dns 
d = sr1(IP(dst="192.168.178.1")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org")))
d.show()


#TCP
ans = sr(IP(dst="192.168.178.1")/TCP(dport=[21,22,23]))
ans.summary()
ans.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%") )
#TCp1 option 1
p = sr(IP(dst="192.168.178.1")/TCP(dport=[21,22,23,80]),inter=0.5,retry=-2,timeout=1)

#TCP SYN
sr1(IP(dst="192.168.178.1")/TCP(dport=80,flags="S"))

ans,unans = srloop(IP(dst="192.168.178.30")/TCP(dport=80,flags="S"),count=10)
#udp


#
ans,unans = srloop(IP(dst="192.168.178.1")/ICMP()/"XXXXXXXXXXX")

import scapy



sniff(filter="icmp and host 192.168.178.1", count=2)


pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))

pkts = sniff(prn=lambda x:x.sprintf("{IP:192.168.178.1-> 192.168.178.50\n}{Raw:%Raw.load%\n}"))


conf.route.delt(net="0.0.0.0/0",gw="192.168.178.254")
conf.route.add(net="0.0.0.0/0",gw="192.168.178.254")
conf.route.add(host="192.168.178.1",gw="192.168.178.1")
conf.route


a, b = sr(IP(dst="192.168.178.1")/TCP(sport=[RandShort()]*1000))


# TCP scan

ans, unans = sr(IP(dst="192.168.178.1")/TCP(dport=[80,666],flags="A"))
ans, unans = sr(IP(dst="192.168.178.50")/TCP(dport=[21,666],flags="A"))


# Xmax
ans, unans = sr(IP(dst="192.168.178.1")/TCP(dport=666,flags="FPU") )

# TCP ack
x = sr1(IP(dst="127.0.0.1")/TCP(dport=80,flags="S"))

send(IP(dst="192.168.178.1", ihl=2, version=3)/ICMP())

res, unans = sr( IP(dst="192.168.178.26")/TCP(flags="S", dport=(1,1024)) )



res, unans = sr( IP(dst="127.0.0.1")/TCP(flags="S", dport=80) )

x = send( fragment(IP(dst="0.0.0.0")/ICMP()/("X"*60000)) )


send(IP(dst="192.168.178.50", ihl=2, version=3)/ICMP()



# srloop

packet = IP(dst='192.168.178.26')/ICMP()
srloop(packet)


# host discover syn

ans,unans=sr( IP(dst="192.168.178.*")/TCP(dport=80,flags="S") )
ans.summary( lambda(s,r) : r.sprintf("%IP.src% is alive") )

#ping ack
 
ans, unans = sr(IP(dst='192.168.178.26')/TCP(dport=80, flags='A')/'XXX')

# arp ping
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.178.0/24"),timeout=2)

#icmp ping

ans,unans=sr(IP(dst="192.168.178.1-50")/ICMP())
ans.summary( lambda(s,r) : r.sprintf("{IP: %IP.src% is alive}") )

