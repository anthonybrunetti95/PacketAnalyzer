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
ssh = sr(IP(dst="192.168.178.50")/TCP(dport=[21,22,23]))

#TCp1 option 1
p = sr(IP(dst="192.168.178.1")/TCP(dport=[21,22,23,80]),inter=0.5,retry=-2,timeout=1)

#TCP SYN
