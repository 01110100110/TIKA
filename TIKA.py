import os
import sys
import socket
import re
import pprint
import nmap
try:
    from ping3 import ping, verbose_ping
except ModuleNotFoundError:
    print("something went wrong. ill call this error 100")


hostname = socket.gethostname()

# Get the IPv4 address corresponding to the hostname
ipv4_address = socket.gethostbyname(hostname)

# Get the IPv6 address corresponding to the hostname
ipv6_address = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]


# Defining stuff///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

def printIP():
    print(f"IPv4 Address: {ipv4_address}")
    print(f"ipv6 Address: {ipv6_address}")

# Check if the IPv4 address can be used
def is_valid_ipv4(ip):
    try:
        # Use the socket library to attempt to create an IPv4 socket with the given IP address
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def is_valid_ipv6(ip):
    try:
        # Use the socket library to attempt to create an IPv6 socket with the given IP address
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False


def pingIPv4():
    # Define the target IP address or hostname
    target_ip = input("What IPv4 address will be pinged? (ex. 1343.1245.9813 or 8.8.8.8 i think)")
    if is_valid_ipv4(target_ip): # Ensure IPv4 is valid
        # Ping the target IP address and print detailed information
        response = verbose_ping(target_ip)

        if response is not None:
            print(response)
        else:
            print("Ping request timed out or failed.")
    else:
        print("Dosent seem like a valid IPv4 address. If you know 100 percent its correct, contact me via github.")

def pingIPv6():
    target_ip = input("What IPv6 address will be pinged? (ex 2001:0db8:85a3:0000:0000:8a2e:0370:7334 i think\n)")
    if is_valid_ipv6(target_ip): # Ensure IPv6 is valid
        responce = verbose_ping(target_ip)

        if responce is not None:
            print(responce)
        else:
            print("Ping Request timed out or failed.")
    else:
        print("Dosent seem like a valid IPv6 address. If you know 100 percent its correct, contact me via github.")

def scanopenports():
    nm = nmap.PortScanner()
    target_ip = input("What is the Target IPv4 address? (ex. 1234.5678.9101 or 8.8.8.8 i think)\n")
    if is_valid_ipv4(target_ip): # Ensure the IP is valid
        # Scan a target IP
        nm.scan(target_ip, arguments="-p 22-80")
        # Print the scan results
        for host in nm.all_hosts():
            print(f"Host: {host}")
            print(f"Open Ports: {nm[host].all_tcp()}")

# End of defining stuff////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

# Logo Cause im just cool like that
print(" ______ _____ __ ___")
print("/_  __/  _/ //_//   |")
print("  / /  / // ,<  / /| |")
print(" / / _/ // /| |/ ___ |")
print("/_/ /___/_/ |_/_/  |_|")
print("Teaching, Industry, Kittens, Always.")

# Choose what to do
runwhat = input("What function should be ran?\n 1. Print your own IP details\n 2. Ping an IPv4 address\n 3. Ping an IPv6 address\n 4. Open port scan(ipv4 only)\n")

  
if runwhat == "1":
    printIP()
elif runwhat == "2":
    pingIPv4()
elif runwhat == "3":
    pingIPv6()
elif runwhat == "4":
    scanopenports()
