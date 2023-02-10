from scapy import route
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import Ether, IP, UDP
from datetime import datetime
import os
import time
import threading



class Sniffer:
	def __init__(self):
		self.fileToSaveLogsName = os.getcwd() + "\\sniffingresult.txt"
		try: open(self.fileToSaveLogsName)
		except: open(self.fileToSaveLogsName, 'w').write('')

		self.fileToSaveLogs = open(self.fileToSaveLogsName, 'a')

		self.WORKING = True

		self.gettedPackets = 0
		self.interface = "eth0"
		self.ifLogs = True

		self.filteredSniffedPackets = {}


	def addToFSP(self, _type):
		try: self.filteredSniffedPackets[_type] += 1
		except: self.filteredSniffedPackets[_type] = 1


	def sniff(self, interface=None, _filter=None):
		if not interface: interface = self.interface

		try:
			scapy.sniff(
				iface=interface, 
				store=False, 
				prn=self.callbackSniffedPacked,
				filter=_filter
			)
		except OSError:
			if self.ifLogs: print('[-] Interface has not been found.')
			return 0 
		except KeyboardInterrupt:
			self.fileToSaveLogs.close()
			self.WORKING = False
			return 0

	def addPacketInfo(self, packet):
		packetInfo = f"\n\n[{str(datetime.now())[:-7]}]"

		if packet.haslayer(Ether):
			packetInfo += f"\nSource MAC (local): {packet[Ether].src}"
			packetInfo += f"\nClient MAC: {packet.dst}"

		if packet.haslayer(IP):
			packetInfo += f"\nSource IP: {packet[IP].src}"
			packetInfo += f"\nClient IP (local): {packet[IP].dst}"

		return packetInfo


	def callbackSniffedPacked(self, packet):
		self.gettedPackets += 1
		if self.ifLogs: print(f'Getted packet. Count of all sniffed packets: {self.gettedPackets}')
		packetInfo = None

		if packet.haslayer(http.HTTPRequest):  # if its http packet
			self.addToFSP('HTTP')

			packetInfo = self.addPacketInfo(packet)

			packetInfo += f"\nMethod: {str(packet.Method)[2:-1]}"
			packetInfo += f"\nURL: {str(packet.Host)[2:-1] + str(packet.Path)[2:-1]}"
			packetInfo += f"\nCookie: {packet.Cookie}"
			packetInfo += f"\nUser_Agent: {packet.User_Agent}"

			if packet.haslayer(scapy.Raw):
				packetInfo += f"\nRaw data: {packet[scapy.Raw]}"
				self.addToFSP('HTTP_RAW')

		if packetInfo:
			self.fileToSaveLogs.write(packetInfo)


	def printInfo(self):
		while True:
			if not self.WORKING: break

			print(f'Saving logs into file named "{self.fileToSaveLogsName}".')

			for key in self.filteredSniffedPackets:
				print(f'Packet`s (type: {key}): {self.filteredSniffedPackets[key]}')

			time.sleep(1)
			if os.name == 'win32': os.system('cls')
			else: os.system('clear')




def main():
	sniffer = Sniffer()
	sniffer.ifLogs = False
	threading.Thread(target=sniffer.printInfo).start()
	sniffer.sniff(interface="Беспроводная сеть")



if __name__ == '__main__': main()