#!/usr/bin/env python3

'''
HTTP Response Scanner
Developed and maintained by Ninad Bandodkar. Code adapted from: https://github.com/internetwache/GitTools/blob/master/Finder/gitfinder.py
Use at your own risk. Usage might be illegal in certain circumstances.
Only for educational purposes!
'''
import requests
import bs4
import re
import argparse
from functools import partial
from multiprocessing import Pool
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
import sys
import ssl
import encodings.idna
import urllib3
urllib3.disable_warnings()

def findit(output_file, domains):
    domain = ".".join(encodings.idna.ToASCII(label).decode("ascii") for label in domains.strip().split("."))

    try:
        # 
        s = requests.Session()
        s.headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'
        url = ''.join(['http://', domain, ':3000'])
        response = s.get(url, verify=False, timeout=5)
        check1 = re.search("grafana", response.text)
        check2 = re.search("grafana", str(response.headers))
        

    except (requests.exceptions.ConnectionError, requests.exceptions.InvalidURL, requests.exceptions.TooManyRedirects):
        return
    except KeyError:
        return
    except OSError:
        return
    except ConnectionResetError:
        return
    except ValueError:
        return
    except (KeyboardInterrupt, SystemExit):
        raise

    # Check for checks
    if (not(check1) and not(check2)):
        return

    # Write match to output_file
    with open(output_file, 'a') as file_handle:
        file_handle.write(''.join([domain, '\n']))

    print(''.join(['[*] Found: ', domain]))


def read_file(filename):
    with open(filename) as file:
        return file.readlines()

def main():
    print("""
###########
# HTTP response Scanner
#
# Developed and maintained by Ninad Bandodkar
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########
""")

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inputfile', default='input.txt', help='input file')
    parser.add_argument('-o', '--outputfile', default='output.txt', help='output file')
    parser.add_argument('-t', '--threads', default=200, help='threads')
    args = parser.parse_args()

    domain_file = args.inputfile
    output_file = args.outputfile
    try:
        max_processes = int(args.threads)
    except ValueError as err:
        sys.exit(err)

    try:
        domains = read_file(domain_file)
    except FileNotFoundError as err:
        sys.exit(err)

    fun = partial(findit, output_file)
    print("Scanning...")
    with Pool(processes=max_processes) as pool:
        pool.map(fun, domains)
    print("Finished")

if __name__ == '__main__':
    main()