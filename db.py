import threading
import time

import pymysql

import config
import util

db_instances = []


def get_db_instance():
    instance = pymysql.connect(**config.mysql_settings)
    db_instances.append(instance)
    return instance


database = get_db_instance()
cursor = database.cursor()
sqls = []
lock = threading.Lock()


def query(sql, callback=None):
    global sqls
    lock.acquire()
    sqls.append((sql, callback))
    lock.release()


def autocommit():
    database.ping(reconnect=True)
    if len(sqls):
        print("[DB] auto commit {} sqls".format(len(sqls)))
        lock.acquire()
        _sqls = sqls.copy()
        sqls.clear()
        lock.release()

        for sql in _sqls:
            try:
                cursor.execute(sql[0])
                if sql[1] is not None:
                    sql[1](cursor.lastrowid)
            except Exception as e:
                print("[DB]", e)

        database.commit()


def close():
    for _database in db_instances:
        _database.commit()
        _database.close()


def get_time():
    return int(time.time())


def init_database():
    init_dns_sql = '''CREATE TABLE IF NOT EXISTS "log_dns" (
          "id" int(11) NOT NULL AUTO_INCREMENT,
          "type" mediumint(9) DEFAULT NULL,
          "client_mac" varchar(17) COLLATE utf8mb4_unicode_ci DEFAULT '',
          "domain" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          "rdata" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          "time" bigint(20) DEFAULT NULL,
          PRIMARY KEY ("id"),
          KEY "id" ("id") USING BTREE,
          KEY "domain" ("domain") USING BTREE,
          KEY "rdata" ("rdata") USING BTREE
        ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;'''

    init_netflow_sql = '''CREATE TABLE IF NOT EXISTS "log_netflow" (
          "id" int(11) NOT NULL AUTO_INCREMENT,
          "client_mac" varchar(17) COLLATE utf8mb4_unicode_ci DEFAULT '',
          "ip_src" varchar(15) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          "ip_dst" varchar(15) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          "port_src" mediumint(9) DEFAULT NULL,
          "port_dst" mediumint(9) DEFAULT NULL,
          "time_start" bigint(20) DEFAULT NULL,
          "time_end" bigint(20) DEFAULT NULL,
          "len" int(11) DEFAULT NULL,
          "pkt_list" mediumtext COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          "type" tinyint(4) DEFAULT NULL,
          "host" varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          PRIMARY KEY ("id"),
          UNIQUE KEY "id" ("id") USING BTREE,
          KEY "ip_dst" ("ip_dst") USING BTREE
        ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;'''

    init_app_sql = '''CREATE TABLE IF NOT EXISTS "log_app" (
          "id" int(11) NOT NULL AUTO_INCREMENT,
          "client_mac" varchar(17) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          "app_name" varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT '',
          "start_time" bigint(20) DEFAULT NULL,
          "end_time" bigint(20) DEFAULT NULL,
          "host" varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
          PRIMARY KEY ("id")
        ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'''

    cursor.execute(init_dns_sql)
    cursor.execute(init_netflow_sql)
    cursor.execute(init_app_sql)
    database.commit()


init_database()
util.add_cron(autocommit, 1)
