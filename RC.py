#script for running CVE scripts

#libraries
from os import system

def run_scripts(ip, service):
	#uruchomienie skryptu (key w dict) from file, umiesc dict w pliku
	with open("CVE_Running_list.txt", "r") as CVErl:
		for line in CVErl:
			keyvalue = line.split(' ')
			if keyvalue[0] == str(services):
				exec(keyvalue[1])
				if keyvalue[2] != "":
					exec(keyvalue[2])
