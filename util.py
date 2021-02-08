import time
from threading import Thread

threads = []
threads_status = []
crontab = []


def add_thread(func):
    global threads
    threads.append(func)


def start_all_thread():
    for thread_func in threads:
        print("[util.thread] start ", thread_func)
        threads_status.append(Thread(target=thread_func))

    for thread in threads_status:
        thread.start()


def add_cron(func, intval):
    print("[util.crond] add {} intval {}".format(func, intval))
    crontab.append({
        "func": func,
        "intval": intval,
        "_": 0
    })


def crond():
    while True:
        time.sleep(1)
        # try:
        for cron in crontab:
            cron["_"] += 1
            if cron["_"] >= cron["intval"]:
                cron["_"] = 0
                try:
                    cron['func']()
                except:
                    continue
        # except Exception as e:
        #     print("[crond] ", e)


add_thread(crond)
