from winevt import EventLog
from datetime import datetime, timedelta
import time
import socket

TCP_IP = 'localhost'
TCP_PORT = 9000
BUFFER_SIZE = 1024


def get_log_line(event):
    pri = (int(event.System.Level.cdata) - 1) * 8 + 0
    version = 1
    timesstamp = event.System.TimeCreated['SystemTime'].split(".")[0]
    hostname = event.System.Computer.cdata
    appname = "Windows"
    procid = "-"
    msgid = "-"
    sd = "[%s %s=\"%s\" %s=\"%s\" %s=\"%s\"]" % \
         ("WSID", "Provider-Name", event.System.Provider['Name'], "EventID", event.System.EventID.cdata, "Channel", event.System.Channel.cdata)
    msg = "-"
    return "<%s>%s %s %s %s %s %s %s %s\n" % (pri, version, timesstamp, hostname, appname, procid, msgid, sd, msg)


def events_in_query(query, last_datetime, s):
    current_datetime = last_datetime

    for event in query:
        line = get_log_line(event)
        current_datetime = event.System.TimeCreated['SystemTime']
        if last_datetime < current_datetime:
            s.sendto(line.encode('utf-8'), (TCP_IP, TCP_PORT))
    return current_datetime


def get_windows_logs():
    interval = 1.0
    start_time = datetime.now() - timedelta(days=1)

    current_datetime_system = start_time.isoformat()
    current_datetime_application = start_time.isoformat()
    current_datetime_security = start_time.isoformat()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))

    while 1:
        query_security = EventLog.Query("C://Windows//System32//winevt//Logs//Security.evtx", "Event/System[Level>0 and Level<=3]")
        query_system = EventLog.Query("C://Windows//System32//winevt//Logs//System.evtx", "Event/System[Level>0 and Level<=3]")
        query_application = EventLog.Query("C://Windows//System32//winevt//Logs//Application.evtx", "Event/System[Level>0 and Level<=3]")

        current_datetime_system = events_in_query(query_system, current_datetime_system, s)
        time.sleep(interval)

        current_datetime_application = events_in_query(query_application, current_datetime_application, s)
        time.sleep(interval)

        current_datetime_security = events_in_query(query_security, current_datetime_security, s)
        time.sleep(interval)

    s.close()


if __name__ == '__main__':
    get_windows_logs()