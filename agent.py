import apache_log_parser
import threading
import socket
import ssl
import time
import json
import re
from datetime import datetime, timedelta
from winevt import EventLog
from pprint import pprint
from _ssl import PROTOCOL_TLSv1_2

TCP_IP = 'localhost'
TCP_PORT = 9000
BUFFER_SIZE = 1024

lock = threading.Lock()


def read_log_file(file):
    interval = 1.0
    while True:
        where = file.tell()
        line = file.readline()
        if not line:
            time.sleep(interval)
            file.seek(where)
        else:
            yield line


def parse_log_line(line, data):
    start_time = datetime.now() - timedelta(minutes=10)
    pri = "-"
    version = 1
    timestamp = datetime.now().isoformat()
    hostname = socket.gethostname()
    appname = data['name']
    procid = "-"
    msgid = "-"
    sd = "-"
    msg = "-"

    if data['name'] == "server":
        pri, sd = parse_server_log(line)
    else:
        sd = ""
        result = re.match(data["pattern"], line)
        if result:
            times = ""
            last = ""
            j = 0
            tokens = line.strip().split(data['splitter'])
            tokens_line = data['line'].split(data['splitter'])
            tokens_time = data['timestamp'].split(data['splitter'])
            if len(tokens) == len(tokens_line):
                for i in range(len(tokens)):
                    if j < len(tokens_time):
                        for t in tokens_time:
                            if tokens_line[i] == t:
                                times += tokens[i]
                                last = tokens_line[i]
                                j += 1
                                if j < len(tokens_time):
                                    times += data['splitter']

                    if tokens_line[i] != "-":
                        if tokens_line[i] != last:
                            sd += tokens_line[i]+"="+"\""+tokens[i] + "\" "

        if sd != "" and times >= start_time.strftime(data['timestr']):
            sd = "[%s %s]" % (data['name']+"SID", sd.strip())
        else:
            sd = "-"

    if pri == "-" and sd == "-":
        return "-"

    return "<%s>%s %s %s %s %s %s %s %s\n" % (pri, version, timestamp, hostname, appname, procid, msgid, sd, msg)


def parse_server_log(line):
    start_time = (datetime.now() - timedelta(minutes=10)).isoformat()
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
    log_line_data = line_parser(line)

    if start_time <= log_line_data['time_received_isoformat']:
        user_agent = log_line_data['request_header_user_agent__browser__family']
        user = log_line_data['remote_user']
        method = log_line_data['request_method']
        status = log_line_data['status']
        timestamp = log_line_data['time_received_isoformat']
        #pprint(log_line_data)
        pri = 3 * 8 + 2
        if status.startswith("5"):
            pri = 1 * 8 + 2

        if status.startswith("4"):
            pri = 2 * 8 + 2

        sd = "[%s %s=\"%s\" %s=\"%s\" %s=\"%s\" %s=\"%s\" %s=\"%s\"]" % \
             ("serverSID", "User-Agent", user_agent, "user", user, "req-method", method, "status", status, "timestamp", timestamp)
        return pri, sd
    else:
        return "-", "-"


def read_logs(log_file, data):
    print(data)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    context = ssl.SSLContext(protocol=PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations("mycert.pem")

    conn = context.wrap_socket(s, server_hostname="localhost", server_side=False)
    conn.connect((TCP_IP, TCP_PORT))

    log_lines = read_log_file(log_file)

    for line in log_lines:
            # only one thread at a time can print to the user
        log_line = parse_log_line(line, data)
        print(log_line)
        if log_line == "-":
            continue
        lock.acquire()
        print(log_line)
        line_bytes = str.encode(log_line)
        conn.send(line_bytes)
        #time.sleep(0.01)
        lock.release()
    conn.close()


def get_log_line(event):
    pri = (int(event.System.Level.cdata) - 1) * 8 + 0
    version = 1
    timesstamp = event.System.TimeCreated['SystemTime'].split(".")[0]
    hostname = event.System.Computer.cdata
    appname = "Windows"
    procid = "-"
    msgid = "-"
    sd = "[%s %s=\"%s\" %s=\"%s\" %s=\"%s\"]" % \
         ("windowsSID", "Provider-Name", event.System.Provider['Name'], "EventID", event.System.EventID.cdata, "Channel", event.System.Channel.cdata)
    msg = "-"
    return "<%s>%s %s %s %s %s %s %s %s\n" % (pri, version, timesstamp, hostname, appname, procid, msgid, sd, msg)


def events_in_query(query, last_datetime,s):
    current_datetime = last_datetime

    for event in query:
        line = get_log_line(event)
        current_datetime = event.System.TimeCreated['SystemTime']
        if last_datetime < current_datetime:
            print(line)
            lock.acquire()
            s.sendto(line.encode('utf-8'), (TCP_IP, TCP_PORT))
            lock.release()
    return current_datetime


def get_windows_logs():
    interval = 1.0
    start_time = datetime.now() - timedelta(minutes=10)

    current_datetime_system = start_time.isoformat()
    current_datetime_application = start_time.isoformat()
    current_datetime_security = start_time.isoformat()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(protocol=PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations("mycert.pem")
    context.load_cert_chain(certfile="mycert.pem", keyfile="mycert.pem", password="secretpassword")

    conn = context.wrap_socket(s, server_hostname="localhost", server_side=False)
    conn.connect((TCP_IP, TCP_PORT))


    while 1:
        query_security = EventLog.Query("C://Windows//System32//winevt//Logs//Security.evtx", "Event/System[Level>0 and Level<=3]")
        query_system = EventLog.Query("C://Windows//System32//winevt//Logs//System.evtx", "Event/System[Level>0 and Level<=3]")
        query_application = EventLog.Query("C://Windows//System32//winevt//Logs//Application.evtx", "Event/System[Level>0 and Level<=3]")

        current_datetime_system = events_in_query(query_system, current_datetime_system,conn)
        time.sleep(interval)

        current_datetime_application = events_in_query(query_application, current_datetime_application,conn)
        time.sleep(interval)

        current_datetime_security = events_in_query(query_security, current_datetime_security,conn)
        time.sleep(interval)

    conn.close()


if __name__ == '__main__':
    data = json.load(open('configuration.json'))

    pprint(data)

    for d in data['configurations']:
        if d['name'] == 'windows':
            get_windows_logs()
        else:
            logfile = open(d['path'], "r")
            t = threading.Thread(target=read_logs, args=(logfile, d,))
            t.start()