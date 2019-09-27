import nmap

def attack(ip):
	nm = nmap.PortScanner()
	arg = "-sU -p 53 --script dns-cache-snoop.nse"
	print("DNS Snoopable... ?")
	nm.scan(ip, arguments=arg)

	print("\t\tResult:")
	print("\t\t\tService: "+nm[ip]['udp'][53]['name'])
	print("\t\t\tState: "+nm[ip]['udp'][53]['state'])
	print("\t\t\tReason: "+nm[ip]['udp'][53]['reason'])
	print("\t\t\tProduct: "+nm[ip]['udp'][53]['product'])
	print("\t\t\tVersion: "+nm[ip]['udp'][53]['version'])
	print("\t\t\tMore Info: "+nm[ip]['udp'][53]['extrainfo'])

	domains = input("Enter the choosen domains(please enter them like this example == domain1,domain2,domain3...): ")
	arg2 = "-sU -p 53 --script dns-cache-snoop.nse --script-args \'dns-cache-snoop.domains={"+domains+"}\'"
	nm.scan(ip, arguments=arg2)
	print("Next snoopable ?")

	print("\t\tResult:")
	print("\t\t\tService: "+nm[ip]['udp'][53]['name'])
	print("\t\t\tState: "+nm[ip]['udp'][53]['state'])
	print("\t\t\tReason: "+nm[ip]['udp'][53]['reason'])
	print("\t\t\tProduct: "+nm[ip]['udp'][53]['product'])
	print("\t\t\tVersion: "+nm[ip]['udp'][53]['version'])
	print("\t\t\tMore Info :" +nm[ip]['udp'][53]['extrainfo'])

	print("Checking which sites have been visited recently ...")
	arg3 = "-sU -p 53 --script dns-cache-snoop.nse --script-args \'dns-cache-snoop.mode=timed\'"
	nm.scan(ip, arguments=arg3)

	print("\t\tResult:")
	print("\t\t\tService: "+nm[ip]['udp'][53]['name'])
	print("\t\t\tState: "+nm[ip]['udp'][53]['state'])
	print("\t\t\tReason: "+nm[ip]['udp'][53]['reason'])
	print("\t\t\tProduct: "+nm[ip]['udp'][53]['product'])
	print("\t\t\tVersion: "+nm[ip]['udp'][53]['version'])
	print("\t\t\tMore Info :" +nm[ip]['udp'][53]['extrainfo'])
