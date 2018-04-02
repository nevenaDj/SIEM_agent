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


def parse_log_line(line):
    tokens = line.split(",")
    pri = int(tokens[1]) * 8 + 3
    version = 1
    timestamp = tokens[2]
    hostname = socket.gethostname()
    appname = "Application"
    procid = "-"
    msgid = "-"
    sd = "[%s %s=\"%s\" %s=\"%s\"]" % \
         ("ASID", "UserID", tokens[0], "PageID", tokens[3])
    msg = tokens[4]
    return "<%s>%s %s %s %s %s %s %s %s" % (pri, version, timestamp, hostname, appname, procid, msgid, sd, msg)


def read_application_logs(file):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))

    for line in read_log_file(open(file)):
        if line.startswith("#"):
            continue

        line = parse_log_line(line)
        line_bytes = str.encode(line)
        s.sendto(line_bytes, (TCP_IP, TCP_PORT))

    s.close()


if __name__ == '__main__':
    read_application_logs("application_logs.txt")