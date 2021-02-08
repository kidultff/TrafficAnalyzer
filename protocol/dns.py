import functools

import db
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.l2 import Ether

dns_query_sql = "INSERT INTO `log_dns` (`client_mac`, `domain`, `time`) VALUE (" \
                "'{client_mac}', '{domain}', {time})"

dns_response_sql = "INSERT INTO `log_dns` (`type`, `client_mac`, `domain`, `rdata`, `time`) VALUE (" \
                   "{type}, '{client_mac}', '{domain}', '{rdata}', {time})"

g_rdata = ""
g_qdata = ""
g_dns_reverse_db_conn = db.get_db_instance()
g_dns_reverse_db_cur = g_dns_reverse_db_conn.cursor()


@functools.lru_cache(10000)
def _dns_reverse(rdata):
    if rdata == g_rdata:
        return g_qdata
    sql = "SELECT `domain` FROM `log_dns` WHERE `rdata`='{}' ORDER BY `id` DESC LIMIT 1"
    if g_dns_reverse_db_cur.execute(sql.format(rdata)):
        return g_dns_reverse_db_cur.fetchall()[0][0]
    return None


def reg_dns_rev_cache(rdata, qdata):
    global g_rdata, g_qdata
    g_rdata = rdata
    g_qdata = qdata
    _dns_reverse(rdata)


def dns_reverse(rdata):
    max_depth = 10
    while True:
        if max_depth == 0:
            return rdata
        _rdata = _dns_reverse(rdata)
        if _rdata is None:
            return rdata
        rdata = _rdata
        max_depth -= 1


def byte2str(s):
    return s if isinstance(s, str) else s.decode()


def clean_dns(s):
    if s[-1] == '.':
        return s[:-1]
    return s


def deal_dns_query(pkt, timestamp):
    qname = clean_dns(byte2str(pkt[DNSQR].qname))
    reg_dns_rev_cache(qname, None)
    res = {
        "client_mac": pkt[Ether].src,
        "domain": qname,
        "time": timestamp
    }
    sql = dns_query_sql.format(**res)
    db.query(sql)
    return True


def deal_dns_response(pkt, timestamp):
    for i in range(pkt[DNS].ancount):
        dnsrr = pkt[DNS].an[i]
        rdata = clean_dns(byte2str(dnsrr.rdata))
        rrname = clean_dns(byte2str(dnsrr.rrname))
        reg_dns_rev_cache(rdata, rrname)
        res = {
            "type": pkt[DNS].an[i].type,
            "client_mac": pkt[Ether].dst,
            "domain": rrname,
            "rdata": rdata,
            "time": timestamp
        }
        sql = dns_response_sql.format(**res)
        db.query(sql)
    return True


def read(pkt, timestamp):
    try:
        if not pkt.haslayer(DNS):
            return False
        if DNSQR in pkt and pkt.dport == 53:
            return deal_dns_query(pkt, timestamp)
        elif DNSRR in pkt and pkt.sport == 53:
            return deal_dns_response(pkt, timestamp)
        return False
    except Exception as e:
        print("[DNS] ", e)
        return False
