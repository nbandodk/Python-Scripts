#! /usr/bin/env python

"""
Script for wordpress identification on a website. 4 checks in place currently.
Work in progress.
Usage: detect-wordpress.py <cname-file> <out-file>

"""

import requests
import bs4
import re
from argparse import ArgumentParser
import urllib3
urllib3.disable_warnings()

def check_site(cname):
    try:
        s = requests.Session()
        s.headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'
        url = ''.join(['http://', cname])
        response = s.get(url, verify=False, timeout=5)

        if response.status_code == 200:
            return response.text
        else:
            return False
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.InvalidURL, requests.exceptions.TooManyRedirects):
        return False


def meta_gen_chk(s):
    
    # create the soup
    soup = bs4.BeautifulSoup(s, "html.parser")
    
    # use regex to find wordpress tag
    test = soup.find_all('meta', {'content': re.compile(r'WordPress.*'), 'name': "generator"})
    
    if test:
    	return True
    else:
        return False


def sitemap_chk(cname):
    
    url=''.join(["http://", cname, "/sitemap.xml"])
    try:
        s = requests.Session()
        s.headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'
        response = s.get(url, verify=False)

        if response.status_code == 200:
            x = re.search("/wp-content/", response.text)
            if x:
                return True
            else:
                return False
        else:
            return False
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return False

def robots_chk(cname):
    
    url=''.join(["http://", cname, "/robots.txt"])
    try:
        s = requests.Session()
        s.headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'
        response = s.get(url, verify=False)

        if response.status_code == 200:
            x = re.search("/wp-admin/", response.text)
            if x:
                return True
            else:
                return False
        else:
            return False
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return False

def wp_chk(r):
    
    x = re.search("/wp-(?:content|includes)/", r)
    if x:
        return True
    else:
        return False
    

def main():
    options = ArgumentParser()
    options.add_argument("input", help='The file contain one domain/cname per line')
    options.add_argument("output", help='Where you would like to save the data')
    args = options.parse_args()
    
    with open(args.input) as f:
        cnames = [line.strip('\n') for line in f]

    outp = []

    for c in cnames:
        response = check_site(c)
        if(response == False):
            continue
        
        else:
            
            mgc = meta_gen_chk(response)
            if mgc:
                print('-> Wordpress meta tag was successfully found for: %s.' % c)

            sitemapc = sitemap_chk(c)
            if sitemapc:
                print('-> Sitemap.xml contains certain indidcators of WordPress CMS for: %s.' % c)
            
            robotsc = robots_chk(c)
            if robotsc:
                print('-> Robots.txt contains certain indidcators of WordPress CMS for: %s.' % c)

            wpc = wp_chk(response)
            if wpc:
                print('-> Website\'s HTML contains certain indidcators of WordPress CMS for: %s.' % c)

            if (mgc == True or sitemapc == True or robotsc == True or wpc == True):
                outp.append('%s -> Potential wordpress Website FOUND' % c)

   

            

    with open(args.output, 'w') as filehandle:
        for listitem in outp:
            filehandle.write('%s\n' % listitem)




if __name__ == '__main__':
    main()