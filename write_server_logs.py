import time
import datetime
import socket
import random


agent = ["Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"]
status = [200, 400, 404, 500, 504]


def generate_log():
    current_dt = datetime.datetime.now()
    current_dt_str = current_dt.strftime("%d/%b/%Y:%H:%M:%S") + " +0100"
    ip = socket.gethostbyname(socket.gethostname())
    referer = "http://www.example.com"
    request = "GET /apache_pb.gif HTTP/1.0"
    username = "frank"
    bytes = random.randint(200,5000)
    i = random.randint(0, 1)
    j = random.randint(0,4)
    return "%s %s %s [%s] \"%s\" %s %s \"%s\" \"%s\"\n" % (ip, "-", username, current_dt_str, request, status[j], bytes, referer, agent[i])


def write_logs(file_name):
    file = open(file_name, "w")
    file.close()
    while 1:
        file = open(file_name, "a")
        file.write(generate_log())
        file.close()
        time.sleep(10)


if __name__ == '__main__':

    write_logs("server_logs.txt")