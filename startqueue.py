import os
import sys

try: qnum = sys.argv[1]
except: qnum = 0 

os.system(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {qnum}")