#!/usr/bin/python3
#####################################################################
# pcapfuzz is a program for attacking services using a packet 
# capture as a template. it helps inject fuzzy strings via 
# three different modes, and offers varying levels of verbosity.
#
# # R - replay mode replays a packet or set of packets 
#          at a service
# # I - insert mode overwrites a set of bytes with a specified value
#          at a specified index into the packet data
# # B - brute force mode inserts a list of strings at each position
#          in a packet
# # S - search mode finds and replaces an existing string with a
#          given string, based on a regular expression.
#
#####################################################################
import sys
import re
import io
import socket
import logging
import time
import argparse
import chardet
import binascii

try: 
  from scapy.all import *
except ImportError:
  print("wooops, I need scapy\ntry: pip3 install scapy")
  sys.exit(0)
  

tcp = True
src_interface = '0.0.0.0'
src_port = 6230
dst_host = '0.0.0.0'
dst_port = 6230
active_socket = None
encoding = ''
hexout = ''
simulate = False

def main():
  args = input_handler()

  #read in files
  packet_templates = rdpcap(args.pcap)
  if args.mode != 'R':
    fuzzstrings = open(args.fuzz_file).readlines()
  iindex = args.inject_index

  #select desired packets
  current_packet_number = 1
  if args.packet_number: #only one to fuzz
    current_packet_number = args.packet_number
    packet_templates = [packet_templates[args.packet_number]]
                                               #stay iterable
  #for each packet, work it
  for packet_template in packet_templates:
    
    #parse the packet, skip if empty
    host_str, raw_data = parse_packet(packet_template, args)
    if not raw_data:
      current_packet_number = current_packet_number + 1
      continue   

    logging.error('~~~~!Testing Packet: ' + str(current_packet_number)+'!~~~~\n\n')
    data_len = len(raw_data)

    #######################
    #replay mode just sends the packet and continues to next packet
    if args.mode == 'R':
      sr_try(raw_data)
      continue
    #######################

    #for each line in fuzz input file
    for fuzz in fuzzstrings:
      logging.error('Fuzz string: ' + fuzz)
      encoded_fuzz = fuzz.strip().encode(encoding)

      #######################
      #insert mode overwrites a specific spot
      if args.mode == 'I':
        malicious = raw_data[:iindex] + encoded_fuzz + raw_data[iindex+len(fuzz):]
        sr_try(malicious)
      #######################

      #######################
      #brute fuzz places the payload in every spot
      if args.mode == 'B':
        for start_index in range(0, data_len):

          end_index = start_index + len(encoded_fuzz)
          malicious = raw_data[:start_index] + encoded_fuzz  + raw_data[end_index:]

          sr_try(malicious)
      #######################

      #######################
      #string replace uses regular expression to find and replace
      if args.mode == 'S':
        encoded_original_string = args.string.encode(encoding)
        malicious = re.sub(encoded_original_string, re.escape(encoded_fuzz), raw_data)
        sr_try(malicious)
      #######################

    logging.error('~!!Done Packet: ' + str(current_packet_number)+'!!~')
    current_packet_number = current_packet_number + 1

#this function sends data to a socket and retrieves the response.
def sr_try(raw_data): 
  response = ''
  banner = ''
  host_str = dst_host + ':' + str(dst_port)

  #if this is a simulation, print the packet and return
  if simulate:
    logging.error("Simulated outbound to " + host_str) 
    print_wrap_supreme(raw_data, "error")
    return
  
  #this makes a new sockete for every comm.
  #probably not optimal for TCP. 
  sock_success = fresh_socket()

  #if we established a connection, check for a banner, 
  #send the message, and then check for a response
  if sock_success:
    #banner handleman ############################
    try:
      banner = active_socket.recv(1024)
      if banner:
        logging.debug("The port sent a banner: " )
        print_wrap_supreme(banner, "debug")
    except Exception as e:
      if "timed out" in str(e):
        logging.debug("Not seeing a banner: " + host_str)
      else:
        logging.error("Got an error workin w/ the banner: " + str(e))

    #send the message ############################
    try:
      time.sleep(1)
    
      logging.warn("Outbound data: " )
      print_wrap_supreme(raw_data, "warn")

      if tcp:
        active_socket.send(raw_data)
        response = active_socket.recv(1024)
      else:
        active_socket.sendto(raw_data, (dst_host, dst_port))
        response, addr = active_socket.recvfrom(1024)

      active_socket.close()
    except Exception as e:
      logging.debug('Comms error with host +' + host_str + '!')
      logging.debug(e)

    #print tha response ##########################
    try:
      if response:
        logging.info(host_str + ' responded to your message with the following: ')
        print_wrap_supreme(response, "info")
        success = True
      else:
        logging.debug(host_str + ' accepted a connection but did not respond to your message.')
    except Exception as e:
      logging.error('Something unexpected happened parsing response from ' + host_str)

#this function builds a socket to the destination host & port.
#it tries thrice to connect, with a 3 second delay between attempts
def fresh_socket():
  global active_socket
  host_str = dst_host + ':' + str(dst_port)
  success = False
  protocol = socket.SOCK_DGRAM
  local_bind_retries = 0
  conn_retries = 0
  max_conn_retries = 3
  max_local_bind_retries = 10

  if active_socket:
    active_socket.close()

  if tcp:
    protocol = socket.SOCK_STREAM

  while (local_bind_retries < max_local_bind_retries and conn_retries < max_conn_retries):
    active_socket = socket.socket(socket.AF_INET, protocol)
    active_socket.settimeout(3)
    active_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
      active_socket.bind((src_interface, src_port))
    except Exception as e:
      logging.debug('could not bind to local iface/port: ' + str(e))
      logging.debug('sleeping for 3s then retrying') 
      time.sleep(3)
      local_bind_retries = local_bind_retries + 1
      continue

    # UDP does not need to connect
    if not tcp:
      return True

    try:
      active_socket.connect((dst_host, dst_port))
      return True
    except Exception as e:
      logging.debug("The following error occured establishing a socket to " + host_str)
      logging.debug(str(e))

      time.sleep(3)
      conn_retries = conn_retries + 1

  if local_bind_retries == max_local_bind_retries:
    logging.error("I couldn't bind to the local port. Something is terribly wrong.")
    sys.exit(0) 

  if conn_retries == max_conn_retries:
    logging.error("Cannot connect to " + host_str + ", on to the next one.")

  return False     

#old printer. will probably mess up your terminal, but does its best
# to represent what it can.
def print_byte_dump(raw_bytes):
  logging.info("".join(map(chr, raw_bytes)))

#Annoyingly, scapy's hexdump just calls print instead of 
#returning a string. soooooooo here's the workaround
def print_wrap_supreme(raw_bytes, level):
  global hexout
  hexdump2(raw_bytes)
  if level == "error":
    logging.error('\n' + hexout)
  elif level == "warn":
    logging.warn('\n' + hexout)
  elif level == "info":
    logging.info('\n' + hexout)
  elif level == "debug":
    logging.debug('\n' + hexout)
  hexout = ''

def hexdump2(x):
  l = len(x)
  i = 0
  while i < l:
    print_to_string("%04x  " % i,end = " ")
    for j in range(16):
      if i+j < l:
        print_to_string("%02X" % orb(x[i+j]), end = " ")
      else:
        print_to_string("  ", end = " ")
      if j%16 == 7:
        print_to_string("", end = " ")
    print_to_string(" ", end = " ")
    print_to_string(sane_color2(x[i:i+16]))
    i += 16

#Annoyingly, scapy's hexdump just calls print instead of 
#returning a string. soooooooo here's the workaround
def sane_color2(x):
  r=""
  for i in x:
    j = orb(i)
    if (j < 32) or (j >= 127):
      r=r+"."
    else:
      r=r+(chb(i).decode('ascii'))
  return r

#Annoyingly, scapy's hexdump just calls print instead of 
#returning a string. soooooooo here's the workaround
def print_to_string(*args, **kwargs):
  global hexout
  output = io.StringIO()
  print(*args, file=output, **kwargs)
  contents = output.getvalue()
  output.close()
  hexout = hexout + contents

def parse_packet(packet_template, args):
  global dst_port
  global dst_host
  global encoding
  global tcp
  layers = list(layerize(packet_template))

  try:
    if "UDP" in layers[2]:
      tcp = False

    if args.target:
      dst_host = args.target
    else:
      dst_host = packet_template[0][layers[1]].dst

    dst_port = packet_template[0][layers[2]].dport
    raw_data = packet_template[0][layers[3]]

    chardet_obj = chardet.detect(bytes(raw_data))
    encoding = chardet_obj['encoding']
    confidence = chardet_obj['confidence']

    if confidence < 1.0:
      logging.error("Not sure about the packet encoding.")
      logging.error("Trying " + encoding + "with confidence " + confidence)

    host_str = dst_host + ':' + str(dst_port)
    return host_str, bytes(raw_data)

  except Exception as e:
    if "list index out of range" in str(e):
      logging.debug("Skipping packet, probably it had no data.")
    else:
      logging.error("An error occured while parsing packet: " + str(e))
      logging.debug("Packet dump: " + hexdump(packet_template))
    return "", ""


#this function helps me out cause 
#there's no abstract reference to layer # in scapy packets.
#sometimes, scapy likes to call the top layer [Raw]. other times
#it tries to define it, like [DNS]
def layerize(packet):
  yield packet.name
  while packet.payload:
    packet = packet.payload
    yield packet.name

def input_handler():
  global simulate
  global src_interface
  global src_port

  desc = """Layer 5+ Fuzzer

Quick examples:
Replay: ./pcapfuzz.py -m R -p x.pcap --target 127.0.0.1 --simulate
Inject: ./pcapfuzz.py -vvv -m I -p x.pcap -f x.txt --inject_index 10 -n 3 
Brutefuzz: ./pcapfuzz.py -vvv --mode B --pcap x.pcap --fuzz x.txt -o outfile.txt
String Replace: ./pcapfuzz.py -vvv -m S --packet_number 3 --fuzz x.txt -p x.pcap --string GET"""

  p = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter)
  p.add_argument('--pcap', 
                  '-p', 
                  required=True, 
                  help='libpcap file containing packet/s to fuzz')
  p.add_argument('--fuzz_file', 
                  '-f',
                  help='newline separated file with fuzz strings')
  p.add_argument('--mode', 
                  '-m', 
                  required=True, 
                  help='R for replay\n' + 
                       'I for inject\n' +
                       'B for brute force\n' +
                       'S for stringfuzz')
  p.add_argument('--target', 
                  '-t', 
                  help='IP address of target system. Will overwrite packet destinations.')
  p.add_argument('--interface', 
                  '-i', 
                  help='the interface or address to bind sockets to')
  p.add_argument('--local_port', 
                  '-l', 
                  type=int, 
                  help='the local port to use')
  p.add_argument('--inject_index', 
                  type=int,
                  help='spot to write into, zero indexed like lists')
  p.add_argument('--string', 
                 '-s',
                  help='string of characters to match and replace with fuzz_file')
  p.add_argument('--simulate', 
                  action='store_true',
                  help='just print the byte layout. this useful for injections to make sure you in the right spot')
  p.add_argument('--packet_number', 
                  '-n',
                  type=int,
                  help='just do one packet from provided pcap. one indexed, like mitch',)
  p.add_argument('--verbosity', 
                  '-v', 
                  action='count', 
                  help='increase verbosity. counts up to -vvv')
  p.add_argument('--out_file', 
                  '-o', 
                  help='file path to write output')

  args = p.parse_args()

  if args.mode in ['I', 'B', 'S']:
    if not args.fuzz_file:
      print("You need --fuzz_file for this mode.")
      sys.exit(0)

  if args.mode == "S":
    if not args.string:
      print("You need a --string for this mode.")
      sys.exit(0)

  if args.interface:
    src_interface = args.interface

  if args.local_port:
    src_port = args.local_port

  ll = logging.ERROR
  if args.verbosity == 1:
    ll = logging.WARNING
  if args.verbosity == 2:
    ll = logging.INFO
  if args.verbosity == 3:
    ll = logging.DEBUG

  if args.simulate:
    simulate = True

  if args.out_file:
    logging.basicConfig(filename=args.out_file,
                        filemode='w',
                        format='%(asctime)s %(message)s', 
                        level=ll)
  else:
    logging.basicConfig(format='%(asctime)s %(message)s', 
                        level=ll)

  return args

main()

#Copyright 2017 John McGuiness
#
#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
