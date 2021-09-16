#!/usr/bin/python3

import nmap

def menu():
	print("1 scan single host")
	print("2 scan in range")
	print("3 scan network")
	print("4 agressive scan")
	print("5 scan ARP packet")
	print("6 scan all ports only")
	print("7 scan in verbose mode")
	print("8 exit")

def scan_single_host():
	nmp=nmap.PortScanner()
	ip=input("Enter ip address")
#	ip='192.168.10.1'
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,ports="1-1000",arguments="-sS -O -v -Pn")
		print(scan)
		print("scanning single host",ip)
		for port in scan["scan"][ip]['tcp'].items():
			print("port",port[0])
			print("state",port[1]['state'])
			print("name",port[1]['name'])
	except:
		print("use sudo")

def scan_range():
	nmp=nmap.PortScanner()
	ip=input("Enter ip address")
	#ip='192.168.10.1'	
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,arguments="-sS -O -Pn")
		print("scanning single host",ip)
		for port in scan["scan"][ip]['tcp'].items():
			print("port",port[0])
			print("state",port[1]['state'])
			print("name",port[1]['name'])
			
	except:
		print("use sudo")

def scan_network():
	nmp=nmap.PortScanner()
	ip=input("Enter ip address")
#	ip='192.168.10.1'
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,arguments="-sS -O -Pn")
		for port in scan['scan'][ip]['osmatch']:
			print("name",port['name'])
			print("accuracy",port['accuracy'])
			print("OSclass",port['osclass'])
	except:
		print("use sudo")

def agressive_scan():
	
	nmp=nmap.PortScanner()
	ip=input("Enter ip address")
#	ip='192.168.10.1'
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,arguments="-sS -O -Pn -T4")
		for port in scan["scan"][ip]['osmatch']:
			print("port",port['name'])
			print("accuracy",port['accuracy'])
			print("OSclass",port['osclass'])
	except:
		print("use sudo")

def arp_packets():
	nmp=nmap.PortScanner()
	ip=input("ip address")
#	ip='192.168.10.1'
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,arguments="-sS -O -PR")
		print(scan)
	except:
		print("use sudo")
def scan_all_ports():
	nmp=nmap.PortScanner()
	ip=input("Enter ip address")
#	ip='192.168.10.1'
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,ports="1-3",arguments="-sS -O -Pn")
		for port in scan["scan"][ip]['tcp'].items():
			print("port",port[0])
			print("state",port[1]['state'])
			print("name",port[1]['name'])
	except:
		print("use sudo")
def scan_verbose():
	nmp=nmap.PortScanner()
	ip=input("Enter ip address")
#	ip='192.168.10.1'
	print("wait.........................")
	try:
		scan=nmp.scan(hosts=ip,arguments="-sS -O -Pn -v")
		for port in scan['scan'][ip]['osmatch']:
			print("Name",port['name'])
			print("Accuracy",port['accuracy'])
			print("OSclass",port['osclass'])
	except:
		print("use sudo")


while True:
	menu()
	ch=int(input("Enter your choice"))

	if ch == 1:
		scan_single_host()
	elif ch ==2:
		scan_range()
	elif ch ==3:
		scan_network()
	elif ch ==4:
		agressive_scan()
	elif ch ==5:
		arp_packets()
	elif ch ==6:
		scan_all_ports()
	elif ch ==7:
		scan_verbose()
	elif ch ==8:
		break;
	else:
		print("Wrong Choice")















