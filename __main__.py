import CloudFlare
import re
import requests
import ipaddress
from example_update_dynamic_dns import do_dns_update
from builtins import str as newstr
import fw_api_test
import argparse
import datetime


def figure_out_public_ip(check_ipv4, check_ipv6):
    ipv6 = None
    ipv4 = None
    data = []
    
    ipv4_address = re.compile('(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
    ipv6_address = re.compile('(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)')

    if check_ipv6:
        ip_response = requests.get('http://ip6.me')
        if "200" in str(ip_response):
            ip_data = ipv6_address.search(str(ip_response.content)).group()
            ip_addr = ipaddress.ip_address(newstr(ip_data))
            if ip_addr.version == 6:
                data.append({"ip":ip_data,"type":'AAAA'})
        else:
            print ('Could not get external IPv6 address')
    if check_ipv4:
        ip_response = requests.get('http://ip4.me')
        if "200" in str(ip_response):
            ip_data = ipv4_address.search(str(ip_response.content)).group()
            ip_addr = ipaddress.ip_address(newstr(ip_data))
            if ip_addr.version == 4:
                data.append({"ip":ip_data,"type":'A'})
        else:
            print ('Could not get external IPv4 address')

    return data     

def establish_cf_connection(email, API_key, zone_name):
    cf = CloudFlare.CloudFlare(email=email,token=API_key)

    try:
        params = {'name':zone_name}
        zones = cf.zones.get(params=params)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones %d %s - api call failed' % (e, e))
    except Exception as e:
        exit('/zones.get - %s - api call failed' % (e))

    if len(zones) == 0:
        exit('/zones.get - %s - zone not found' % (zone_name))

    if len(zones) != 1:
        exit('/zones.get - %s - api call returned %d items' % (zone_name, len(zones)))

    zone = zones[0]

    zone_id = zone['id']

    return cf, zone_id

parser = argparse.ArgumentParser()

parser.add_argument('--un', action='store', dest='un', 
                    help='Username for FW')
parser.add_argument('--pw', action='store', dest='pw',
                    help='Password for FW access')
parser.add_argument('--fw', action='store', dest='fw',default=None,
                    help='FW IP address')
parser.add_argument('--rule', action='store', dest='rule',
                    help='Rule object name in FW')
parser.add_argument('--token', action='store', dest='token',required=True,
                    help='CF token')
parser.add_argument('--email', action='store', dest='email',required=True,
                    help='CF email')
parser.add_argument('--zone', action='store', dest='zone',required=True,
                    help='CF DNS zone')
parser.add_argument('--hosts', nargs='+', dest='hosts',required=True,
                    help='List of space separated hosts to update')
parser.add_argument('--ipv4', dest='ipv4', action='store_true', help='Only do IPv4 reconds')
parser.add_argument('--ipv6', dest='ipv6', action='store_true', help='Only do IPv6 records')
parser.add_argument('--noproxy', dest='proxy', action='store_false', help='Do not use CF proxy for the update')

args = parser.parse_args()

check_ipv6 = True
check_ipv4 = True

if args.ipv4:
    check_ipv6=False
if args.ipv6:
    check_ipv4=False

now = datetime.datetime.now()
print (now)

print ('Figuring out public IP')
ip_data = figure_out_public_ip(check_ipv4, check_ipv6)

print ('Working with cloudflare')
cf, zone_id = establish_cf_connection(args.email, args.token, args.zone)
for dns_name in args.hosts:
    for ip in ip_data:
            do_dns_update(cf, args.zone, zone_id, "{}.{}".format(dns_name, args.zone), ip['ip'], ip['type'], args.proxy)

if args.fw:
    print ('Updating FW records')
    for ip in ip_data:
        if ip['type'] == 'AAAA':
            try:
                t = fw_api_test.fortigate_api(args.fw, args.un, args.pw)
                addr = t.show(['cmdb', 'firewall', 'address6', args.rule])
                g_ip = addr['results'][0]['ip6']
                if g_ip == ip['ip']+'/128':
                    print ('IPv6 on FW is set up properly')
                else:
                    print('Setting up IP on FW')
                    push = t.edit(['cmdb', 'firewall', 'address6', args.rule], data={'ip6':ip['ip']})
                    t.print_data (push)  
            except:
                print ('something went wrong')
                raise
