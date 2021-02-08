import queue

import config
import db
import util
from protocol import dns, tcp, udp, app
from scapy.all import *

pkt_queue = queue.Queue()


def deal_pkt():
    cnt = 0
    while True:
        try:
            pkt, timestamp = pkt_queue.get()
            if not dns.read(pkt, timestamp):
                udp.read(pkt, timestamp)
                tcp.read(pkt, timestamp)
        except Exception as e:
            print("[deal_pkt] ", e)


def _sniff():
    while True:
        sniff(iface=config.interface, prn=lambda pkt: pkt_queue.put((pkt, int(time.time()))), count=100)


if __name__ == '__main__':
    util.add_thread(deal_pkt)
    util.add_thread(_sniff)
    util.start_all_thread()

try:
    while True:
        time.sleep(10)
        print("queue size: {} , TCP sess: {}, UDP sess: {}, APP sess: {}"
              .format(pkt_queue.qsize(), len(tcp.sessions), len(udp.sessions), len(app.sessions)))

except KeyboardInterrupt:
    db.close()
    print("Bye")
    exit()
