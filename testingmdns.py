#!/usr/bin/python3
  
import dns.rdatatype
import dns.rdataclass
import dns.query
import dns.message
import re
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("input", help = "input filename of a file containing ip addresses or domains")
parser.add_argument("output", help = "output filename")
args = parser.parse_args()

with open(args.input) as f:
        ip_list = [line.strip('\n') for line in f]

l=[]

qname = dns.name.from_text("_http._tcp.local")
q = dns.message.make_query(qname, dns.rdatatype.PTR)

for ip in ip_list:
        try:
                r = dns.query.udp(q, ip, port=5353, timeout=3)
                check1 = re.search("BrightSign", str(r))
                if check1:
                        l.append(str(ip))
        except:
                pass

with open(args.output, 'w') as filehandle:
        for listitem in l:
            filehandle.write('%s\n' % listitem)