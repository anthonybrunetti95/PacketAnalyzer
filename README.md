The author  Anthony Brunetti and date  10/21/20
This project was done in python 3.8.6.
The libraries used are:
os
scapy (v. 2.4.4)
collections
time
logging
matplotlib
csv

Function sniff_interface
This function sniffing IP traffic based on the  selected network interface is the protocol you want.

Function randomIP
function that randomly generates the ip source

Function randInt
function that randomly generates the ip source

Function attack_syn_flood
this function performs an ack-syn-flood attack.
Sending syn requests to the server without responding to the ack

Function os_fingerprinting_load
this function loads a small db in a cvs file relative to the default ttl values 
for each operating system into a data structure

Function os_fingerprinting
In this function it is delegated to look for the os fingerprinting based  on the ttl value. Discrimination and recognition can be improved by  using the other fields of the IP and ICMP packet header. (Reference https://www.defcon.org/images/defcon-10/dc-10-presentations/dc10-arkin-xprobe.pdf slide where it explains how to identify the operating system using the ip and icmp header fields)

Function send_ICMP
Send an packet ICMP 

Function get_mac
Function that return mac adress through ip adress

Function scan_udp
Function scan of open ports via a UDP packet


Function scan_port_host
scan of open ports via a function report_ports() function integrated scapy


Function dection_syn_flood
this function collects all TCP packets containing the SYN fag. And it will produce a list with all hosts making the most TCP-SYN requests. This check is used to check for suspicious activity and indications of TCP-SYN packets. To have an efficient control system on SYN flood attacks, it is necessary to check the time between requests and the other of the same ip address. Average all requests from clients to the server.
(Reference  page 36 chapter 3.3  Mitigation Methods)
