import time
import datetime
import random

username = ["pera", "mika", "zika", "jova", "mare"]
page = ["login", "registration", "restorants", "users", "restorant"]
message = ["Invalid username or password", "Username already exists", "Something went wrong"]


def generate_log():
    current_dt = datetime.datetime.now()
    current_dt_str = current_dt.strftime("%Y-%m-%dT%H:%M:%S")
    i = random.randint(0, 4)
    j = random.randint(0, 4)
    if i > 1:
        return "%s,%s,%s,%s,%s\n" % (username[j], "1", current_dt_str, page[i], message[2])
    else:
        return "%s,%s,%s,%s,%s\n" % (username[j], "1", current_dt_str, page[i], message[i])


def write_logs(file_name):
    file = open(file_name, "w")
    file.close()
    while 1:
        file = open(file_name, "a")
        file.write(generate_log())
        file.close()
        time.sleep(10)


if __name__ == '__main__':
    write_logs("application_logs.txt")