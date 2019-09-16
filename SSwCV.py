'''
SSwCV - Scanning Script with Check Vulns

###########################################
Created by Dawid Wordliczek (WolfMan12333)
###########################################

This tool is created only for automation of basic
scanning with nmap and basic scanning vulns of founded
services/ports.
My own script mainly for OSCP exam.
'''


import nmap
from CVEs import *
from CVEss import *
from os import system
from os import path
from time import sleep

#############################################################################################################################
#Scanning Functions
############################################################################################################################
#function creating file and writing result of scan to it
def create_and_writing_file(scan_result, f_name):
	#text file
	name = f_name + ip + '.txt'
	fo = open(name, "w")
	fo.write(scan_result)
	fo.close()
	name_csv = f_name + ip + ".csv"
	fo_csv = open(name_csv, "w")
	fo_csv.write(nm.csv())
	fo_csv.close()

#nmap -sn <ip>
def disable_port_scan(ip):
	nm.scan(ip, arguments='-sn')
	print('\t\tHostName: ' + nm[ip].hostname())
	print('\t\tState: ' + nm[ip].state())
	fo = open("disable_port_scan.txt", "w")
	fo.write('HostName: ' + nm[ip].hostname() + '\nState: ' + nm[ip].state() + '\n')
	fo.close()

#nmap result scan of ssh
def res_nmap_ssh(ip):
	print('\t\tSSH:\n\t\t\tService: '+nm[ip]['tcp'][22]['name'])
	print('\t\t\tState: '+nm[ip]['tcp'][22]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][22]['reason'])
	print('\t\t\tProduct: '+nm[ip]['tcp'][22]['product'])
	print('\t\t\tVersion: ' +nm[ip]['tcp'][22]['version'])
	print('\t\t\tMore Info: '+nm[ip]['tcp'][22]['extrainfo'])
	ret_f_txt = ""

	try:
		print('\t\t\tssh-hostkey:')
		print('\t\t\t\t'+nm[ip]['tcp'][22]['script']['ssh-hostkey'])
		ret_f_txt = "SSH:\n\t\tService: "+nm[ip]['tcp'][22]['name']+"\n\t\tState: "+nm[ip]['tcp'][22]['state']+"\n\t\tReason: "+nm[ip]['tcp'][22]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][22]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][22]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][22]['extrainfo']+"\n\t\tssh-hostkey: \n\t\t\t\t"+nm[ip]['tcp'][22]['script']['ssh-hostkey']+"\n"
	except:
		ret_f_txt = "SSH:\n\t\tService: "+nm[ip]['tcp'][22]['name']+"\n\t\tState: "+nm[ip]['tcp'][22]['state']+"\n\t\tReason: "+nm[ip]['tcp'][22]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][22]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][22]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][22]['extrainfo']+"\n"

	create_and_writing_file(ret_f_txt, "nmap-ssh-report")

#nmap result scan of smtp
def res_nmap_smtp(ip):
	print("\t\tSMTP:")
	print("\t\t\tService: "+nm[ip]['tcp'][25]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][25]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][25]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][25]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][25]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][25]['extrainfo'])
	ret_f_txt = "SMTP:\n\t\tService: "+nm[ip]['tcp'][25]['name']+"\n\t\tState: "+nm[ip]['tcp'][25]['state']+"\n\t\tReason: "+nm[ip]['tcp'][25]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][25]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][25]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][25]['extrainfo']+"\n"
	create_and_writing_file(ret_f_txt, "nmap-smtp-report")

#nmap result scan of http
def res_nmap_http(ip):
	print("\t\tHTTP:")
	print("\t\t\tService: "+nm[ip]['tcp'][80]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][80]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][80]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][80]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][80]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][80]['extrainfo'])
	ret_f_txt = ""

	try:
		print("\t\t\tHTTP Server Header: "+nm[ip]['tcp'][80]['script']['http-server-header'])
		print("\t\t\tHTTP Title: "+nm[ip]['tcp'][80]['script']['http-title'])
		print("\t\t\tHTTP Favicon: "+nm[ip]['tcp'][80]['script']['http-favicon'])
		print("\t\t\tHTTP Methods: "+nm[ip]['tcp'][80]['script']['http-methods'].replace("\n", ""))
		ret_f_txt = "HTTP:\n\t\tService: "+nm[ip]['tcp'][80]['name']+"\n\t\tState: "+nm[ip]['tcp'][80]['state']+"\n\t\tReason: "+nm[ip]['tcp'][80]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][80]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][80]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][80]['extrainfo']+"\n\t\tHTTP Server Header: "+nm[ip]['tcp'][80]['script']['http-server-header']+"\n\t\tHTTP Title: "+nm[ip]['tcp'][80]['script']['http-title']+"\n\t\tHTTP Favicon: "+nm[ip]['tcp'][80]['script']['http-favicon']+"\n\t\tHTTP Methods: "+nm[ip]['tcp'][80]['script']['http-methods'].replace("\n", "")+"\n"
	except:
		ret_f_txt = "HTTP:\n\t\tService: "+nm[ip]['tcp'][80]['name']+"\n\t\tState: "+nm[ip]['tcp'][80]['state']+"\n\t\tReason: "+nm[ip]['tcp'][80]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][80]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][80]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][80]['extrainfo']+"\n"

	create_and_writing_file(ret_f_txt, "nmap-http-report")

#nmap result scan of 9929 port
def res_nmap_ggzg(ip):
        print("\t\t9929 port:")
        print("\t\t\tService: "+nm[ip]['tcp'][9929]['name'])
        print("\t\t\tState: "+nm[ip]['tcp'][9929]['state'])
        print("\t\t\tReason: "+nm[ip]['tcp'][9929]['reason'])
        print("\t\t\tProduct: "+nm[ip]['tcp'][9929]['product'])
        print("\t\t\tVersion: "+nm[ip]['tcp'][9929]['version'])
        print("\t\t\tMore Info: "+nm[ip]['tcp'][9929]['extrainfo'])
        ret_f_txt = "9929 port:\n\t\tService: "+nm[ip]['tcp'][9929]['name']+"\n\t\tState: "+nm[ip]['tcp'][9929]['state']+"\n\t\tReason: "+nm[ip]['tcp'][9929]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][9929]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][9929]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][9929]['extrainfo']+"\n"
        create_and_writing_file(ret_f_txt, "nmap-9929port-report")

#nmap result scan of 31337 port
def res_nmap_eieet(ip):
	print("\t\t31337 port:")
	print("\t\t\tService: "+nm[ip]['tcp'][31337]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][31337]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][31337]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][31337]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][31337]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][31337]['extrainfo'])
	ret_f_txt = "31337 port:\n\t\tService: "+nm[ip]['tcp'][31337]['name']+"\n\t\tState: "+nm[ip]['tcp'][31337]['state']+"\n\t\tReason: "+nm[ip]['tcp'][31337]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][31337]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][31337]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][31337]['extrainfo']+"\n"
	create_and_writing_file(ret_f_txt, "nmap-31337port-report")

#nmap result scan of 443 https
def res_nmap_https(ip):
	print("\t\tHTTPS port:")
	print("\t\t\tService: "+nm[ip]['tcp'][443]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][443]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][443]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][443]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][443]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][443]['extrainfo'])
	ret_f_txt = "HTTPS port:\n\t\tService: "+nm[ip]['tcp'][443]['name']+"\n\t\tState: "+nm[ip]['tcp'][443]['state']+"\n\t\tReason: "+nm[ip]['tcp'][443]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][443]['product']+"\n\t\tProduct: "+nm[ip]['tcp'][443]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][443]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][443]['extrainfo']+"\n"
	create_and_writing_file(ret_f_txt, "nmap-https-report")

#nmap result scan of 8080 proxy?
def res_nmap_proxy(ip):
	print("\t\t8080 port:")
	print("\t\t\tService: "+nm[ip]['tcp'][8080]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][8080]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][8080]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][8080]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][8080]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][8080]['extrainfo'])
	ret_f_txt = "HTTPS port:\n\t\tService: "+nm[ip]['tcp'][8080]['name']+"\n\t\tState: "+nm[ip]['tcp'][8080]['state']+"\n\t\tReason: "+nm[ip]['tcp'][8080]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][8080]['product']+"\n\t\tProduct: "+nm[ip]['tcp'][8080]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][8080]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][8080]['extrainfo']+"\n"
	create_and_writing_file(ret_f_txt, "nmap-8080port-report")

#nmap result scan of 33283 port
def res_nmap_eezbe(ip):
	print("\t\t33283 port: ")
	print("\t\t\tService: "+nm[ip]['tcp'][33283]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][33283]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][33283]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][33283]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][33283]['version'])
	pritn("\t\t\tMore Info: "+nm[ip]['tcp'][33283]['extrainfo'])
	ret_f_txt = "33283 port:\n\t\tService: "+nm[ip]['tcp'][33283]['name']+"\n\t\tState: "+nm[ip]['tcp'][33283]['state']+"\n\t\tReason: "+nm[ip]['tcp'][33283]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][33283]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][33283]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][33283]['extrainfo']+"\n"
	create_and_writing_file(ret_f_txt, "nmap-33283port-report")

#nmap result scan of 51463 port
def res_nmap_ziabe(ip):
	print("\t\t51463 port: ")
	print("\t\t\tService: "+nm[ip]['tcp'][51463]['name'])
	print("\t\t\tState: "+nm[ip]['tcp'][51463]['state'])
	print("\t\t\tReason: "+nm[ip]['tcp'][51463]['reason'])
	print("\t\t\tProduct: "+nm[ip]['tcp'][51463]['product'])
	print("\t\t\tVersion: "+nm[ip]['tcp'][51463]['version'])
	print("\t\t\tMore Info: "+nm[ip]['tcp'][51463]['extrainfo'])
	ret_f_txt = "51463 port:\n\t\tService: "+nm[ip]['tcp'][51463]['name']+"\n\t\tState: "+nm[ip]['tcp'][51463]['state']+"\n\t\tReason: "+nm[ip]['tcp'][51463]['reason']+"\n\t\tProduct: "+nm[ip]['tcp'][51463]['product']+"\n\t\tVersion: "+nm[ip]['tcp'][51463]['version']+"\n\t\tMore Info: "+nm[ip]['tcp'][51463]['extrainfo']+"\n"
	create_and_writing_file(ret_f_txt, "nmap-51463port-report")

#nmap result scan OS information
def res_nmap_os_info(ip):
	value = str(nm[ip]['osmatch'])
	value = value.replace('[', "")
	value = value.replace(']', "")
	value = value.replace('{', "")
	value = value.replace('}', "")
	value = value.replace('\'', "")
	value = value.replace(',', "\n")
	print(value)

#def res_nmap_udp_port
def res_nmap_udp_port(ip, ars):
	for i in ars.split(','):
		if i != ",":
			i = i.replace('\'', "")
			print("\t\t"+i+" port: ")
			i = int(i)
			print("\t\t\tService: "+nm[ip]['udp'][i]['name'])
			print("\t\t\tState: "+nm[ip]['udp'][i]['state'])
			print("\t\t\tReason: "+nm[ip]['udp'][i]['reason'])
			print("\t\t\tProduct: "+nm[ip]['udp'][i]['product'])
			print("\t\t\tVersion: "+nm[ip]['udp'][i]['version'])
			print("\t\t\tMore Info: "+nm[ip]['udp'][i]['extrainfo'])
			i = str(i)
			ret_f_txt = i
			i = int(i)
			ret_f_txt += " port:\n\t\tService: "+nm[ip]['udp'][i]['name']+"\n\t\tState: "+nm[ip]['udp'][i]['state']+"\n\t\tReason: "+nm[ip]['udp'][i]['reason']+"\n\t\tProduct: "+nm[ip]['udp'][i]['product']+"\n\t\tVersion: "+nm[ip]['udp'][i]['version']+"\n\t\tMore Info: "+nm[ip]['udp'][i]['extrainfo']+"\n"
			i = str(i)
			fn = "nmap-"+i+"port-udp-report"
			create_and_writing_file(ret_f_txt, fn)

#more data from scan tcp
def more_data(array, ip):
	for ports in array:
		check_ports(ports)

#more data from scan ip
def more_data_ip(array, ip):
	for ports in array:
		check_ports_ip(ports)

#more data from scan sctp
def more_data_sctp(array, ip):
	for ports in array:
		check_ports_sctp(ports)

#check tcp ports
def check_ports(ports):
	with open("dpsn.txt", "r") as dpsn:
		for line in dpsn:
			keyvalue = line.split(' ')
			if keyvalue[0] == str(ports):
				exec(keyvalue[1])

#check ip ports
def check_ports_ip(ports):
	with open("dpsn_ip.txt", "r") as dpsn:
		for line in dpsn:
			keyvalue = line.split(' ')
			if keyvalue[0] == str(ports):
				exec(keyvalue[1])

#check sctp ports
def check_ports_sctp(ports):
	with open("dpsn_sctp.txt", "r") as dpsn:
		for line in dpsn:
			keyvalue = line.split(' ')
			if keyvalue[0] == str(ports):
				exec(keyvalue[1])

#nmap -A <ip>
#scan 1024 most common ports, run OS detection, run default nmap scripts
#of formats in the current directory
def common_ports_scan(ip):
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments='-A')
	print('\t\tHostName: ' + nm[ip].hostname())
	print('\t\tState: ' + nm[ip].state())
	print('\t\tProtocols: ' + str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'tcp' in services:
		print('\t\tTCP: ' + str(nm[ip].all_tcp()))
		ports = nm[ip].all_tcp().copy()
		more_data(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected ports choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'udp' in services:
		print('\t\tUDP: ' + str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		more_data_udp(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected ports choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'ip' in services:
		print('\t\tIP: ' + str(nm[ip].all_ip()))
		ports = nm[ip].all_ip().copy()
		more_data_ip(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected ports choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'sctp' in services:
		print('\t\tSCTP: ' + str(nm[ip].all_sctp()))
		ports = nm[ip].all_sctp().copy()
		more_data_sctp(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected ports choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

#nmap -v -p- -sT <ip>
#scan all 65535 ports on $targetip with full connect scan
def all_ports(ip):
	print("\t\tIt can take a while!!!")
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments='-v -p- -sT')
	print('\t\tHostName: ' + nm[ip].hostname())
	print('\t\tState: ' + nm[ip].state())
	print('\t\tProtocols: ' + str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'tcp' in services:
		print('\t\tTCP: ' + str(nm[ip].all_tcp()))
		ports = nm[ip].all_tcp().copy()
		more_data(ports, ip)
		ns = input("If you want to scan detected ports choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'udp' in services:
		print('\t\tUDP: ' + str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		more_data_udp(ports, ip)
		ns = input("If you want to scan detected ports choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'ip' in services:
		print('\t\tIP: ' + str(nm[ip].all_ip()))
		ports = nm[ip].all_ip().copy()
		more_data_ip(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'sctp' in services:
		print('\t\tSCTP: ' + str(nm[ip].all_sctp()))
		ports = nm[ip].all_sctp().copy()
		more_data_sctp(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

#nmap -v -sV -O -sS -T4 <ip>
#prints verbose, runs stealth syn scan, T4 timing, OS and version detection
def VSTOS(ip):
	print("\t\tIt can take a while!!!")
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments='-v -sV -O -sS -T4')
	print('\t\tHostName: ' +nm[ip].hostname())
	print('\t\tState: ' +nm[ip].state())
	print('\t\tProtocols: '+str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'tcp' in services:
		print('\t\tTCP: '+str(nm[ip].all_tcp()))
		ports = nm[ip].all_tcp().copy()
		more_data(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'udp' in services:
		print('\t\tUDP: ' +str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		more_data_udp(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'ip' in services:
		print('\t\tIP: '+str(nm[ip].all_ip()))
		ports = nm[ip].all_ip().copy()
		more_data_ip(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'sctp' in services:
		print('\t\tSCTP: ' +str(nm[ip].all_sctp()))
		ports = nm[ip].all_sctp().copy()
		more_data_sctp(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

#nmap -v -sV -p- -T4 -A <ip>
#prints verbose, OS and version detection, all ports, T4
def VOSAT(ip):
	print("\t\tIt can take a while!!!")
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments='-v -sV -p- -T4 -A')
	print('\t\tHostName: ' +nm[ip].hostname())
	print('\t\tState: ' +nm[ip].state())
	print('\t\tProtocols: '+str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'tcp' in services:
		print('\t\tTCP: '+str(nm[ip].all_tcp()))
		ports = nm[ip].all_tcp().copy()
		more_data(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'udp' in services:
		print('\t\tUDP: ' +str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		more_data_udp(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'ip' in services:
		print('\t\tIP: '+str(nm[ip].all_ip()))
		ports = nm[ip].all_ip().copy()
		more_data_ip(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'sctp' in services:
		print('\t\tSCTP: ' +str(nm[ip].all_sctp()))
		ports = nm[ip].all_sctp().copy()
		more_data_sctp(ports, ip)
		res_nmap_os_info(ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

#nmap -v -sT -p- -T4 <ip>
#prints verbose, TCP connect scan, all ports, timing T4
def VTAT(ip):
	print("\t\tIt can take a while!!!")
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments='-v -sT -p- -T4')
	print('\t\tHostName: ' +nm[ip].hostname())
	print('\t\tState: ' +nm[ip].state())
	print('\t\tProtocols: '+str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'tcp' in services:
		print('\t\tTCP: '+str(nm[ip].all_tcp()))
		ports = nm[ip].all_tcp().copy()
		more_data(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'udp' in services:
		print('\t\tUDP: ' +str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		more_data_udp(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'ip' in services:
		print('\t\tIP: '+str(nm[ip].all_ip()))
		ports = nm[ip].all_ip().copy()
		more_data_ip(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'sctp' in services:
		print('\t\tSCTP: ' +str(nm[ip].all_sctp()))
		ports = nm[ip].all_sctp().copy()
		more_data_sctp(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

#nmap -v -sU -p- -T4 <ip>
#prints verbose, UDP Scanning, all ports and T4 timing
def VUAT(ip):
	p = input("\t\tPlease give a port number or series of ports separated by comma: ")
	arg = "-v -sU -p" + p + " -T4"
	print("\t\tIt can take a while!!!")
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments=arg)
	print("\t\tHostName: "+nm[ip].hostname())
	print("\t\tState: "+nm[ip].state())
	print("\t\tProtocols: "+str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'udp' in services:
		print("\t\tUDP: "+str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		res_nmap_udp_port(ip, p)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')
	else:
		print("\t\tThere's no UDP protocol opened here!!")

#nmap -v -sS -sC -A -p- <ip>
#prints verbose, TCP SYN scan,  performing a script scan using the default set of scripts
def VTPerform(ip):
	print("\t\tIt can take a while!!!")
	print("\t\tPlease wait ...")
	nm.scan(ip, arguments='-v -sS -sC -A -p-')
	print('\t\tHostName: ' +nm[ip].hostname())
	print('\t\tState: ' +nm[ip].state())
	print('\t\tProtocols: '+str(nm[ip].all_protocols()))
	services = list()
	services = nm[ip].all_protocols().copy()
	ports = list()

	if 'tcp' in services:
		print('\t\tTCP: '+str(nm[ip].all_tcp()))
		ports = nm[ip].all_tcp().copy()
		more_data(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'udp' in services:
		print('\t\tUDP: ' +str(nm[ip].all_udp()))
		ports = nm[ip].all_udp().copy()
		more_data_udp(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'ip' in services:
		print('\t\tIP: '+str(nm[ip].all_ip()))
		ports = nm[ip].all_ip().copy()
		more_data_ip(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

	if 'sctp' in services:
		print('\t\tSCTP: ' +str(nm[ip].all_sctp()))
		ports = nm[ip].all_sctp().copy()
		more_data_sctp(ports, ip)
		ns = input("If you want to scan detected port choose:scan\nElse choose ns:")
		if ns == 'scan':
			print("Scanning menu is creating ...")
			sleep(5)
			system('clear')
			create_vuln_menu(ports)
		elif ns == 'ns':
			print("Returning to Main Menu ...")
			sleep(5)
			system('clear')
		else:
			print("This command doesn\'t exist!!!")
			sleep(5)
			system('clear')

########################################################################################################################
#Function creating menu
########################################################################################################################
def create_vuln_menu(array):
	system('clear')

	ans = True
	while ans:
		print("\t\t\tDetected ports!!!\n\t\t\tChoose by entering number of port\n\t\t\tor use exit command to leave: ")

		for x in array:
			print("\t\t\tService: " + str(x), end='\n')

		ans = input("\t\t\t")

		if ans == "exit":
			print("\t\t\tExiting from scanning basic vulns of ports")
			sleep(5)
			ans = None
		elif int(ans) in array:
			with open("dpscv.txt", "r") as dpscv:
				for line in dpscv:
					keyvalue = line.split(' ')
					if keyvalue[0] == str(ans):
						exec(keyvalue[1])
						try:
						#if keyvalue[2] != None:
							exec(keyvalue[2])
						except:
							print("There\'s no more functions for this services.")
		else:
			print("Not Valid Choice!!! Try Again!!!")

########################################################################################################################
#Main Function
########################################################################################################################
if __name__ == "__main__":
	nm = nmap.PortScanner()
	print("\t\tPlease give Victim IP address: ")
	ip = input('\t\t')

	#clear term
	system('clear')

	ans = True
	while ans:
		system('clear')
		print("""
		1.Scanning without port scanning
		2.Scanning 1024 most common ports, OS detection, default scripts and save the results in number of formats
		3.Scanning all 65535 ports with full connect scan
		4.Scanning with verbose, runs stealth syn scan, T4 timing, OS and version detection
		5.Scanning with verbose, all ports, T4 timing, OS and version detection
		6.Scanning with verbose, TCP connect scan, all ports and T4 timing
		7.Scanning with verbose, UDP Scanning, all ports and T4 timing
		8.Scanning with verbose, TCP SYN scan and performing a script scan using the default set of scripts
		9.Exit
		""")
		ans=input("\t\tChoose scanning option: ")
		if ans == "1":
			disable_port_scan(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "2":
			common_ports_scan(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "3":
			all_ports(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "4":
			VSTOS(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "5":
			VOSAT(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "6":
			VTAT(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "7":
			VUAT(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "8":
			VTPerform(ip)
			print("\t\tScanning is Finished!!!")
			input()
		elif ans == "9":
			print("\n\t\tSSwCV shutting down!!!")
			sleep(5)
			system('clear')
			ans = None
		else:
			print("\nNot Valid Choice Try again")
