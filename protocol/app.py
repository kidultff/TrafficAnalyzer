import copy
import time

import config
import db
import util

app_start_sql = "INSERT INTO `log_app` (`client_mac`, `start_time`, `end_time`, `app_name`, `host`)" \
                " VALUE ('{client_mac}', {start_time}, 0, '{app_name}', '{host}')"
app_end_sql = "UPDATE `log_app` SET `end_time`={end_time} where `id`={row_id}"
g_features = {
    "TCP": [],
    "UDP": []
}
sessions = {}
item = {
    "client_mac": "",
    "start_time": 0,
    "end_time": 0,
    "app_name": "",
    "host": "",
    "row_id": 0,
}


def load_features():
    file = open('features.txt', encoding='utf-8')
    line_cnt = 0
    while True:
        line_cnt += 1
        try:
            line = file.readline()
            if not line:
                break
            if line.replace(' ', '')[0] == '#':
                continue
            _idx = line.find(':')
            app_name, features = line[:_idx], line[_idx + 1:].replace('[', '').replace(']', ''). \
                replace('\n', '').split(',')
            if len(features) == 0 or app_name == '':
                continue
            for feature in features:
                proto, sport, dport, host, dic = feature.split(';')
                dic = [i.split(':') for i in dic.split('|')]
                if proto.upper() == 'TCP':
                    g_features['TCP'].append((app_name, sport, dport, host, dic))
                if proto.upper() == 'UDP':
                    g_features['UDP'].append((app_name, sport, dport, host, dic))
        except Exception as e:
            print("[Load Features] error in line", line_cnt)
            print("[Load Features]", e)
            print("[ERROR] Features.txt is not a valid feature file!")
            exit(-1)
    file.close()
    print("[Load Features] features.txt load successful")


def get_features(type):
    return g_features[type]


def add(client_mac, app_name, timestamp, host):
    k = client_mac + app_name
    if k in sessions:
        sessions[k]['end_time'] = timestamp
    else:
        sessions[k] = copy.deepcopy(item)
        sessions[k]['client_mac'] = client_mac
        sessions[k]['app_name'] = app_name
        sessions[k]['start_time'] = timestamp
        sessions[k]['end_time'] = timestamp
        sessions[k]['host'] = host
        write_db_start(k)


def app_check_time_out():
    print("[APP] check app timeout")
    _del = []
    for item in sessions:
        if int(time.time()) - sessions[item]['end_time'] >= config.app_timeout:
            write_db_end(item)
            _del.append(item)

    for item in _del:
        del sessions[item]


def write_db_start(item):
    res = sessions[item]
    sql = app_start_sql.format(**res)

    def callback(x):
        sessions[item]["row_id"] = x

    db.query(sql, callback)


def write_db_end(item):
    res = sessions[item]
    sql = app_end_sql.format(**res)
    db.query(sql)


load_features()
util.add_cron(app_check_time_out, 60)
