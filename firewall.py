from datetime import datetime, timedelta
import time
import socket

TCP_IP = 'localhost'
TCP_PORT = 9000
BUFFER_SIZE = 1024


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


def get_log_line(tokens):
    date = tokens[0]
    time = tokens[1]
    action = tokens[2]
    protocol = tokens[3]
    src_ip = tokens[4]
    dst_ip = tokens[5]
    src_port = tokens[6]
    dst_port = tokens[7]
    path = tokens[16]

    pri = 4 * 8 + 1
    version = 1
    timestamp = "%sT%s" % (date, time)
    hostname = socket.gethostname()
    appname = "Firewall"
    procid = "-"
    msgid = ""

    if path.strip() == "SEND":
        msgid = "%s%s" % (protocol, "OUT")
    if path.strip() == "RECEIVE":
        msgid = "%s%s" % (protocol, "IN")

    sd = "[%s %s=\"%s\" %s=\"%s\" %s=\"%s\" %s=\"%s\"]" % \
         ("FSID", "src_ip", src_ip, "dst_ip", dst_ip, "src_port", src_port, "dst_port", dst_port)
    msg = action
    return "<%s>%s %s %s %s %s %s %s %s\n" % (pri, version, timestamp, hostname, appname, procid, msgid, sd, msg)


def read_firewall_logs(file):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))

    start_time = datetime.now() - timedelta(hours=1)
    current_datetime = start_time.isoformat()

    for line in read_log_file(open(file)):
        if line.startswith("#"):
            continue

        tokens = line.split(" ")
        if len(tokens) != 17:
            continue

        timestamp = "%sT%s" % (tokens[0], tokens[1])

        if current_datetime < timestamp:
            line = get_log_line(tokens)
            print(line)
            line_bytes = str.encode(line)
            s.sendto(line_bytes, (TCP_IP, TCP_PORT))
            time.sleep(0.01)

    s.close()


if __name__ == '__main__':
    read_firewall_logs("C:\Windows\System32\LogFiles\Firewall\pfirewall.log")