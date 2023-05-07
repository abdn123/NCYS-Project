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
import urllib
from urllib.parse import urlparse

RATE_LIMIT_WINDOW = 0
RATE_LIMIT_THRESHOLD = 0  

# Initialize a dictionary to store the old values
old_values = {
    'RATE_LIMIT_THRESHOLD': RATE_LIMIT_THRESHOLD,
    'BLOCK_RULES': {'port': [], 'mac': [], 'webpage': []},
    'BLACKLIST': []
}

request_counts = {}

# define database name
DATABASE_NAME = "D:\\University work\\6th Semester\\NCYS\\example.db"

logging.basicConfig(filename='D:\\University work\\6th Semester\\NCYS\\waf.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def is_ip_blacklisted(ip):
    if ip in old_values['BLACKLIST']:
        return True
    else:
        return False
    
def add_to_blacklist(ip):
    old_values['BLACKLIST'].append(ip)
    logging.warning("Added {} to blacklist.".format(ip))

def check_block_rules(port, mac, webpage):

    if port in old_values['BLOCK_RULES']['port']:
        logging.warning("Blocking request on port: {}".format(port))
        return True

    if mac in old_values['BLOCK_RULES']['mac']:
        logging.warning("Blocking request from MAC address: {}".format(mac))
        return True

    if webpage in old_values['BLOCK_RULES']['webpage']:
        logging.warning("Blocking request to webpage: {}".format(webpage))
        return True

    return False

def filter_xss_payload(value):
    # Basic check for potential XSS payloads
    value = urllib.parse.unquote_plus(value)
    xss_patterns = ["<script>", "</script>", "img", "javascript:", "onerror=", "onload=", "<iframe>", "<body>", "<h1>"]
    for pattern in xss_patterns:
        if pattern.lower() in value.lower():
            return ""
    return value

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

            if request_counts[client_ip] > old_values['RATE_LIMIT_THRESHOLD']:
                logging.warning("Blocking request from IP: {} due to rate limit threshold exceeded.".format(client_ip))
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'403 Forbidden - Rate limit threshold exceeded.')
            else:
                
                # referer = self.headers.get('Referer')
                # if referer:
                #     parsed_url = urlparse(referer)
                #     requested_page = parsed_url.path
                #     print("Requested Page:", requested_page)

                if check_block_rules(self.server.server_port, client_mac, self.headers.get('host')):
                    logging.warning("Blocking request from IP: {} due to matching blocking rule.".format(client_ip))
                    self.send_response(403)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'403 Forbidden - Request matches blocking rule.')
                else:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()

                    if "?" in self.path:
                        # Get user input from the URL query string
                        query = self.path.split("?")[1]
                        params = {}
                        for param in query.split("&"):
                            key, value = param.split("=")
                            params[key] = value

                        # Filter user input for potential XSS payloads
                        filtered_params = {}
                        for key, value in params.items():
                            filtered_value = filter_xss_payload(value)
                            if filtered_value == "":
                                # XSS payload detected, send 403 response
                                logging.warning("XSS payload detected: {}".format(value))
                                self.send_response(403)
                                self.send_header('Content-type', 'text/html')
                                self.end_headers()
                                self.wfile.write(b'403 Forbidden - XSS payload detected.')
                                return
                            filtered_params[key] = filtered_value

                        # Perform SQL query with filtered parameters to prevent SQL injection
                        with sqlite3.connect(DATABASE_NAME) as conn:
                            c = conn.cursor()
                            c.execute("INSERT INTO users (name, age) VALUES (?, ?)",
                                    (filtered_params.get("name", ""), filtered_params.get("age", "")))
                            conn.commit()

                    self.wfile.write(b'200 OK - Request allowed.')


        
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

    # Get the old values from the config file if present
    if 'RATE_LIMIT_THRESHOLD' in config:
        old_values['RATE_LIMIT_THRESHOLD'] = int(config['RATE_LIMIT_THRESHOLD']['threshold'])
    if 'BLACKLIST' in config:
        old_values['BLACKLIST'] = config['BLACKLIST']['ips']
        old_values['BLACKLIST'] = [ip.strip() for ip in old_values['BLACKLIST'].split(',')]
    if 'BLOCK_RULES' in config:
        block_ports = [port.strip() for port in config['BLOCK_RULES']['ports'].split(',')]
        block_macs = [mac.strip() for mac in config['BLOCK_RULES']['macs'].split(',')]
        block_webpage = [webpage.strip() for webpage in config['BLOCK_RULES']['webpage'].split(',')]
        old_values['BLOCK_RULES'] = {'port': block_ports, 'mac': block_macs, 'webpage': block_webpage}

    while True:
        print("1. Configure Rate Limit threshold (Current value: {})".format(old_values['RATE_LIMIT_THRESHOLD']))
        print("2. Configure Blacklist (Current value: {})".format(old_values['BLACKLIST']))
        print("3. Configure Blocking Rules (Current value: {})".format(old_values['BLOCK_RULES']))
        print("4. Remove from Configuration")
        print("5. Save Configuration")
        print("6. Exit")

        choice = input("Enter your choice (1/2/3/4/5/6): ")

        if choice == '1':
            current_value = old_values['RATE_LIMIT_THRESHOLD']
            new_value = input("Enter rate limit threshold (current value is {}): ".format(current_value))
            if new_value:
                old_values['RATE_LIMIT_THRESHOLD'] = int(new_value)

        elif choice == '2':
            current_value = old_values['BLACKLIST']
            new_value = input("Enter comma-separated list of IPs to blacklist (current value is {}): ".format(current_value))
            if new_value:
                new_ips = [ip.strip() for ip in new_value.split(',')]
                old_values['BLACKLIST'].extend(new_ips)

        elif choice == '3':
            current_value = old_values['BLOCK_RULES']
            block_ports = input("Enter comma-separated list of ports to block (current value is {}): ".format(current_value['port']))
            block_macs = input("Enter comma-separated list of MAC addresses to block (current value is {}): ".format(current_value['mac']))
            block_webpage = input("Enter comma-separated list of webpages to block (current value is {}): ".format(current_value['webpage']))
            
            # Create a new dictionary to store the updated blocking rules
            new_block_rules = {'port': current_value['port'].copy(), 'mac': current_value['mac'].copy(), 'webpage': current_value['webpage'].copy()}

            if block_ports:
                new_block_rules['port'].extend([port.strip() for port in block_ports.split(',')])
            if block_macs:
                new_block_rules['mac'].extend([mac.strip() for mac in block_macs.split(',')])
            if block_webpage:
                new_block_rules['webpage'].extend([webpage.strip() for webpage in block_webpage.split(',')])

            old_values['BLOCK_RULES'] = new_block_rules
            print("Blocking rules updated successfully.")

        elif choice == '4':
            print("1. Remove Rate Limit threshold")
            print("2. Remove Blacklist")
            print("3. Remove Blocking Rules")

            remove_choice = input("Enter your choice (1/2/3): ")

            if remove_choice == '1':
                if 'RATE_LIMIT_THRESHOLD' in config:
                    del config['RATE_LIMIT_THRESHOLD']
                    old_values['RATE_LIMIT_THRESHOLD'] = 0
                    print("Rate limit threshold removed successfully.")
                else:
                    print("Rate limit threshold not found in the configuration file.")

            elif remove_choice == '2':
                if 'BLACKLIST' in config:
                    ip_to_remove = input("Enter the IP address to remove from the blacklist: ")
                    if ip_to_remove in old_values['BLACKLIST']:
                        old_values['BLACKLIST'].remove(ip_to_remove)
                        config['BLACKLIST']['BLACKLIST'] = ','.join(old_values['BLACKLIST'])
                        with open('D:\\University work\\6th Semester\\NCYS\\config.ini', 'w') as configfile:
                            config.write(configfile)
                        print("IP address removed from the blacklist successfully.")
                    else:
                        print("IP address not found in the blacklist.")
                else:
                    print("Blacklist not found in the configuration file.")

            elif remove_choice == '3':
                if 'BLOCK_RULES' in config:
                    block_type = input("Enter the type of data to remove (port/mac/webpage): ")
                    data_to_remove = input(f"Enter the {block_type} to remove: ")
                    if block_type in old_values['BLOCK_RULES'] and data_to_remove in old_values['BLOCK_RULES'][block_type]:
                        old_values['BLOCK_RULES'][block_type].remove(data_to_remove)
                        config['BLOCK_RULES'][block_type] = ','.join(old_values['BLOCK_RULES'][block_type])
                        print(f"{block_type} removed successfully.")
                    else:
                        print(f"{block_type} not found in the blocking rules.")
                else:
                    print("Blocking rules not found in the configuration file.")

        elif choice == '5':
            config['RATE_LIMIT_THRESHOLD'] = {'threshold': str(old_values['RATE_LIMIT_THRESHOLD'])}
            config['BLACKLIST'] = {'ips': ','.join(old_values['BLACKLIST'])}
            config['BLOCK_RULES'] = {'ports': ','.join(old_values['BLOCK_RULES']['port']),
                                     'macs': ','.join(old_values['BLOCK_RULES']['mac']),
                                     'webpage': ','.join(old_values['BLOCK_RULES']['webpage'])}
            with open('D:\\University work\\6th Semester\\NCYS\\config.ini', 'w') as configfile:
                config.write(configfile)
            print("Configuration saved successfully.")

        elif choice == '6':
            return

        else:
            print("Invalid choice. Please try again.")
            
                
if __name__ == "__main__":
    waf_server = threading.Thread(target=start_waf_server, args=(4444,))
    waf_server.start()
    configure_waf_settings()
    