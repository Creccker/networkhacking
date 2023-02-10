import scapy.all as scapy
import sys
import re



def findMacByIP(ip, protocol=None, broadcast='ff:ff:ff:ff:ff:ff', timeout=1, logs=False):
	arpRequest = scapy.ARP(pdst=ip)  # Creating packet
	if logs: print("ARP packet has format: " + arpRequest.summary())

	broadcast = scapy.Ether(dst=broadcast)  # To send packet
	if logs: print('Sending [FROM > TO]: ' + broadcast.summary())

	finalPacket = broadcast / arpRequest
	if logs: print('Final packet has "' + finalPacket.summary() + '" format.')

	answeredPackets, unansweredPackets = scapy.srp(finalPacket, timeout=timeout)  # sending packet (and receive some)

	if logs: answeredPackets.summary()

	foundedMacs = {}

	if logs: print('\n\n __________________________________________')
	for answeredPacketIndex in range(len(answeredPackets)):
		mac = answeredPackets[answeredPacketIndex][1].hwsrc
		ip = answeredPackets[answeredPacketIndex][1].psrc

		if logs: print(f'| {"0" + str(answeredPacketIndex + 1) if answeredPacketIndex < 10 else answeredPacketIndex + 1} | {" " * (15 - len(ip)) + ip} | {mac} |')
		foundedMacs[ip] = mac

	if logs: print('|____|_________________|___________________|')

	return foundedMacs


if __name__ == '__main__':
	ip = sys.argv[1]

	protocol = None
	try: protocol = sys.argv[2] if sys.argv[2] != 'None' else None
	except: pass

	timeout = 1
	try: timeout = float(sys.argv[3])
	except: pass

	findMacByIP(ip, protocol=protocol, timeout=timeout, logs=True)