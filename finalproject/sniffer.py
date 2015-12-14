# Mathurshan Vimalesvaran
# Sniffs network for plaintext personal data

from scapy.all import *
import re
import argparse

parser = argparse.ArgumentParser(description='Sniff network for plaintext personal data')
parser.add_argument('-n', help='output data for credit cards and social security numbers (many false positives)', action='store_true')
args = parser.parse_args()
last_printed = ''

'''
Look for important private information
'''
def packet_callback(packet):
    # check to make sure it has a data payload
    if packet[TCP].payload:
        parsed_packet = str(packet[TCP].payload).lower()
        parsed_packet = parsed_packet.replace('user-agent', '')

        if 'user' in parsed_packet:
            start = parsed_packet.index('user')
            print_data(parsed_packet, start, 'username')
        if 'pass' in parsed_packet:
            start = parsed_packet.index('pass')
            print_data(parsed_packet, start, 'password')
        if 'email' in parsed_packet:
            start = parsed_packet.index('email')
            print_data(parsed_packet, start, 'email')

        if args.n:
            # Social Security Number
            ssn_re = re.compile("\d{3}-?\d{2}-?\d{4}")
            ssn_found = ssn_re.search(parsed_packet)
            if ssn_found:
                print_data(ssn_found.group(0), 0, 'SSN')

            # Visa, MasterCard, AmEx, Diners Club, Discover, and JCB respectively
            cc_re = re.compile("(4[0-9]{12}(?:[0-9]{3})|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})")
            cc_found = cc_re.search(parsed_packet)
            if cc_found:
                print_data(cc_found.group(0), 0, 'credit card')

'''
Output info available to sniffers
'''
def print_data(packet, start, data_type):
    global last_printed
    num_to_print = 32

    if last_printed != packet[start:start+num_to_print]:
        print "Sniffed potential " + data_type + ": " + packet[start:start+num_to_print] + "\n"

    last_printed = packet[start:start+num_to_print]

sniff(filter="tcp", prn=packet_callback, store=0)