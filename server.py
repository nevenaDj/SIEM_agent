import apache_log_parser
import time
import socket
from pprint import pprint

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
    line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
    log_line_data = line_parser(line)

    user_agent = log_line_data['request_header_user_agent__browser__family']
    user = log_line_data['remote_user']
    method = log_line_data['request_method']
    status = log_line_data['status']
    timestamp = log_line_data['time_received_isoformat']
    #pprint(log_line_data)
    pri = 4 * 8 + 2
    if status.startswith("5"):
        pri = 1 * 8 + 2

    if status.startswith("4"):
        pri = 2 * 8 + 2

    version = 1
    hostname = socket.gethostname()
    appname = "Server"
    procid = "-"
    msgid = "-"
    sd = "[%s %s=\"%s\" %s=\"%s\" %s=\"%s\" %s=\"%s\"]" % \
         ("SSID", "User-Agent", user_agent, "user", user, "req-method", method, "status", status)
    msg = "-"
    return "<%s>%s %s %s %s %s %s %s %s\n" % (pri, version, timestamp, hostname, appname, procid, msgid, sd, msg)


def read_server_logs(file):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))

    for line in read_log_file(open(file)):
        line = parse_log_line(line)
        line_bytes = str.encode(line)
        s.sendto(line_bytes, (TCP_IP, TCP_PORT))

    s.close()


if __name__ == '__main__':
    read_server_logs("server_logs.txt")

