import json

import config
import db
import util
from protocol import app
from protocol import dns
from scapy.all import *
from scapy.layers.dns import DNS

tcp_sql = "INSERT INTO `log_netflow` (`client_mac`, `ip_src`, `ip_dst`, `port_src`, `port_dst`, `pkt_list`," \
          " `len`, `time_start`, `time_end`, `type`, `host`)" \
          "VALUE ('{client_mac}', '{ip_src}', '{ip_dst}', {port_src}, {port_dst}, '{pkt_list}', " \
          "'{len}', '{time_start}', '{time_end}', 17, '{host}')"

sessions = {}
item = {
    "client_mac": "",
    "ip_src": "",
    "ip_dst": "",
    "port_src": 0,
    "port_dst": 0,
    "time_start": 0,
    "time_end": 0,
    "len": 0,
    "pkt_list": [],
    "host": ""
}


def write_db(session):
    res = {
        "client_mac": session["client_mac"],
        "ip_src": session["ip_src"],
        "ip_dst": session['ip_dst'],
        "port_src": session['port_src'],
        "port_dst": session['port_dst'],
        "pkt_list": json.dumps(session['pkt_list']),
        "len": session['len'],
        "time_start": session['time_start'],
        "time_end": session['time_end'],
        "host": session['host']
    }
    sql = tcp_sql.format(**res)
    db.query(sql)
    return True


def deal_tcp(pkt, timestamp):
    # basic info
    client_mac = pkt[Ether].src
    ip_src = str(pkt["IP"].src)
    ip_dst = str(pkt["IP"].dst)
    port_src = str(pkt["UDP"].sport)
    port_dst = str(pkt["UDP"].dport)
    payload_len = len(pkt['UDP'].payload)
    sequin_str = ','.join([ip_src, port_src, ip_dst, port_dst])
    rev_sequin_str = ','.join([ip_dst, port_dst, ip_src, port_src])

    # exist session
    if sequin_str in sessions:
        pkt_dir = 1
    elif rev_sequin_str in sessions:
        sequin_str = rev_sequin_str
        pkt_dir = 2

    # new session
    else:
        pkt_dir = 1
        sessions[sequin_str] = copy.deepcopy(item)
        sessions[sequin_str]["client_mac"] = client_mac
        sessions[sequin_str]["ip_src"] = ip_src
        sessions[sequin_str]["ip_dst"] = ip_dst
        sessions[sequin_str]["port_src"] = port_src
        sessions[sequin_str]["port_dst"] = port_dst
        sessions[sequin_str]["time_start"] = timestamp
        sessions[sequin_str]["host"] = dns.dns_reverse(ip_dst)

    session = sessions[sequin_str]

    # check app
    if pkt_dir == 1:
        tcp_features = app.get_features("UDP")
        for feature in tcp_features:
            app_name, sport, dport, host, dic = feature
            flag = True
            if sport != '' and sport != str(session['port_src']):
                continue
            if dport != '' and dport != str(session['port_dst']):
                continue
            if host != '' and host not in session['host']:
                continue
            flag = True
            try:
                for d in dic:
                    if len(d) == 2 and pkt['UDP'].payload.load[int(d[0])] != int(d[1], 16):
                        flag = False
                        break
            except:
                flag = False
            if flag:
                app.add(client_mac, app_name, timestamp, sessions[sequin_str]["host"])
                break

    # write session record
    session['len'] += payload_len
    session['time_end'] = timestamp
    session['pkt_list'].append({
        "d": pkt_dir,
        "l": payload_len,
        "t": timestamp - session['time_start']
    })
    return True


def udp_timeout():
    print("[UDP] check udp timeout")
    _del = []
    for session in sessions:
        if int(time.time()) - sessions[session]["time_end"] >= config.udp_timeout:
            write_db(sessions[session])
            _del.append(session)
    for i in _del:
        del sessions[i]


util.add_cron(udp_timeout, 60)


def read(pkt, timestamp):
    try:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return False
        if pkt.haslayer(DNS):
            return False
        return deal_tcp(pkt, timestamp)
    except Exception as e:
        print("[UDP] ", e)
        return False
