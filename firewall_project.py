import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.server import SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import ssl
import logging
import configparser
import sqlite3
import html


RATE_LIMIT_WINDOW = 0
RATE_LIMIT_THRESHOLD = 0  

request_counts = {}

BLACKLIST = []

BLOCK_RULES = {'port': [], 'mac': [], 'website': []}

# define database name
DATABASE_NAME = "example.db"

# create table if not exists
with sqlite3.connect(DATABASE_NAME) as conn:
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)""")

logging.basicConfig(filename='D:\\University work\\6th Semester\\NCYS\\waf.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def is_ip_blacklisted(ip):
    if ip in BLACKLIST:
        return True
    else:
        return False
    
def add_to_blacklist(ip):
    BLACKLIST.append(ip)
    logging.warning("Added {} to blacklist.".format(ip))

def check_block_rules(port, mac, website):

    if port in BLOCK_RULES['port']:
        logging.warning("Blocking request on port: {}".format(port))
        return True

    if mac in BLOCK_RULES['mac']:
        logging.warning("Blocking request from MAC address: {}".format(mac))
        return True

    if website in BLOCK_RULES['website']:
        logging.warning("Blocking request to website: {}".format(website))
        return True

    return False

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        client_mac = self.headers.get('mac-address')

        if is_ip_blacklisted(client_ip):
            logging.warning("Blocking request from blacklisted IP: {}".format(client_ip))
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'403 Forbidden - Your IP is blacklisted.')
        else:
            if client_ip in request_counts:
                request_counts[client_ip] += 1
            else:
                request_counts[client_ip] = 1

            if request_counts[client_ip] > RATE_LIMIT_THRESHOLD:
                logging.warning("Blocking request from IP: {} due to rate limit threshold exceeded.".format(client_ip))
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'403 Forbidden - Rate limit threshold exceeded.')
            else:
                if check_block_rules(self.server.server_port, client_mac, self.headers.get('host')):
                    logging.warning("Blocking request from IP: {} due to matching blocking rule.".format(client_ip))
                    self.send_response(403)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'403 Forbidden - Request matches blocking rule.')
                else:
                    current_time = int(time.time())
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    # get user input from the URL query string
                    query = self.path.split("?")[1]
                    params = {}
                    for param in query.split("&"):
                        key, value = param.split("=")
                        params[key] = value

                    # filter user input for XSS
                    name = html.escape(params["name"]) if "name" in params else ""
                    age = html.escape(params["age"]) if "age" in params else ""

                    # perform SQL query with parameters to prevent SQL injection
                    with sqlite3.connect(DATABASE_NAME) as conn:
                        c = conn.cursor()
                        c.execute("INSERT INTO users (name, age) VALUES (?, ?)", (name, age))
                        conn.commit()

                    
                    self.wfile.write(b'200 OK - Request allowed.')
                    request_counts[client_ip] = current_time
        
    def log_message(self, format, *args):
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def start_waf_server(port):
    server_address = ("localhost", port)
    httpd = ThreadedHTTPServer(server_address, MyHTTPRequestHandler)
    #httpd.socket = ssl.wrap_socket(httpd.socket, certfile='D:\\University work\\6th Semester\\NCYS\\server.pem', server_side=True, ssl_version=ssl.PROTOCOL_SSLv23)
    logging.info('Starting WAF server on port {}'.format(port))
    httpd.serve_forever()

def configure_waf_settings():    
    global RATE_LIMIT_THRESHOLD
    global BLOCK_RULES
    global BLACKLIST

    config = configparser.ConfigParser()
    config.read('D:\\University work\\6th Semester\\NCYS\\config.ini')
    if 'RATE_LIMIT_THRESHOLD' in config:
        RATE_LIMIT_THRESHOLD = int(config['RATE_LIMIT_THRESHOLD']['threshold'])
        print(RATE_LIMIT_THRESHOLD)
    if 'BLACKLIST' in config:
        BLACKLIST = config['BLACKLIST']['ips']
        BLACKLIST = [ip.strip() for ip in BLACKLIST.split(',')]
        print(BLACKLIST)
    if 'BLOCK_RULES' in config:
        block_ports = [port.strip() for port in config['BLOCK_RULES']['ports'].split(',')]
        block_macs = [mac.strip() for mac in config['BLOCK_RULES']['macs'].split(',')]
        block_websites = [website.strip() for website in config['BLOCK_RULES']['websites'].split(',')]
        BLOCK_RULES = {'port': block_ports, 'mac': block_macs, 'website': block_websites}
        print(BLOCK_RULES)

    while True:
        print("1. Configure Rate Limit threshold")
        print("2. Configure Blacklist")
        print("3. Configure Blocking Rules")
        print("4. Remove from Configuration")
        print("5. Save Configuration")
        print("6. Exit")

        choice = input("Enter your choice (1/2/3/4/5/6): ")
        
        if choice == '1':
            rate_limit_threshold = int(input("Enter rate limit threshold: "))
            RATE_LIMIT_THRESHOLD = rate_limit_threshold
            print("Rate limit threshold updated successfully.")

        elif choice == '2':
            blacklist = input("Enter comma-separated list of IPs to blacklist: ")
            add_to_blacklist(blacklist)
            print("Blacklist updated successfully.")

        elif choice == '3':
            block_ports = input("Enter comma-separated list of ports to block: ")
            block_macs = input("Enter comma-separated list of MAC addresses to block: ")
            block_websites = input("Enter comma-separated list of websites to block: ")

            BLOCK_RULES = {'port': [], 'mac': [], 'website': []}
            BLOCK_RULES['port'] = [port.strip() for port in block_ports.split(',')]
            BLOCK_RULES['mac'] = [mac.strip() for mac in block_macs.split(',')]
            BLOCK_RULES['website'] = [website.strip() for website in block_websites.split(',')]
            print("Blocking rules updated successfully.")
            
        elif choice == '4':
            print("1. Remove Rate Limit threshold")
            print("2. Remove Blacklist")
            print("3. Remove Blocking Rules")

            remove_choice = input("Enter your choice (1/2/3): ")

            if remove_choice == '1':
                if 'RATE_LIMIT_THRESHOLD' in config:
                    del config['RATE_LIMIT_THRESHOLD']
                    RATE_LIMIT_THRESHOLD = None
                    print("Rate limit threshold removed successfully.")
                else:
                    print("Rate limit threshold not found in configuration file.")

            elif remove_choice == '2':
                if 'BLACKLIST' in config:
                    ip_to_remove = input("Enter the IP address to remove from the blacklist: ")
                    if ip_to_remove in BLACKLIST:
                        BLACKLIST.remove(ip_to_remove)
                        config['BLACKLIST']['ips'] = ','.join(BLACKLIST)
                        with open('D:\\University work\\6th Semester\\NCYS\\config.ini', 'w') as configfile:
                            config.write(configfile)
                        print("IP address removed from blacklist successfully.")
                    else:
                        print("IP address not found in the blacklist.")
                else:
                    print("Blacklist not found in configuration file.")

            elif remove_choice == '3':
                if 'BLOCK_RULES' in config:
                    block_type = input("Enter the type of data to remove (port/mac/website): ")
                    data_to_remove = input(f"Enter the {block_type} to remove: ")
                    if block_type in BLOCK_RULES and data_to_remove in BLOCK_RULES[block_type]:
                        BLOCK_RULES[block_type].remove(data_to_remove)
                        config['BLOCK_RULES'][block_type] = ','.join(BLOCK_RULES[block_type])
                        print(f"{block_type} removed successfully.")
                    else:
                        print(f"{block_type} not found in the blocking rules.")
                else:
                    print("Blocking rules not found in configuration file.")
                          
        elif choice == '5':
            config['RATE_LIMIT_THRESHOLD'] = {'threshold': str(RATE_LIMIT_THRESHOLD)}
            config['BLACKLIST'] = {'ips': ','.join(BLACKLIST)}
            config['BLOCK_RULES'] = {'ports': ','.join(BLOCK_RULES['port']), 'macs': ','.join(BLOCK_RULES['mac']), 'websites': ','.join(BLOCK_RULES['website'])}
            with open('D:\\University work\\6th Semester\\NCYS\\config.ini', 'w') as configfile:
                config.write(configfile)
            print("Configuration saved successfully.")

        elif choice == '6':
            break

        else:
            print("Invalid choice. Please try again.") 
            
                
if __name__ == "__main__":
    waf_server = threading.Thread(target=start_waf_server, args=(4444,))
    waf_server.start()
    configure_waf_settings()
    