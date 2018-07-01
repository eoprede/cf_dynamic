# Automating updates of CF records and FW address objects
This script will automatically determine public IPv4 and IPv6 addresses of the system it is run on and then will update Fortigate Firewall address6 object with current IPv6 address.

## Use case
I have an internet connection at home that support IPv6, which means that I can have nearly unlimited public IPs to serve some content.
However, these IPv6 addresses can change dynamically at ISPs mercy, thus I need some methods for keeping them up to date. Traditional ddns solutions don't really work because they don't support IPv6. On top of that, I have discovered that Linux hosts upon change of IPv6 address, hold on to their old addresses as well. So asking the system for its IPv6 address is not reliable and instead I have to use some external service like ip4.me and ip6.me
Once the IPv6 address is updated, I need to be able to adjust firewall settings to allow the traffic to the new host. 

## Manual
Just run this script on the host that has connection and optionally to the fortigate firewall.
    Example script run:
```
python cf_dynamic --un fw_un --pw fw_pw --fw 192.168.1.1 --rule test_address --token cf_api_token --email cf_email.com --zone mydomain.com --hosts host1 host2 --ipv6 
```
Variables:
```
--un Username for FW account (probably best to lock account down, as it is executed from host seving data to the Internet)
--pw Passwowrd for FW account
--fw IP or DNS name for the Fortigate Firewall. Optional value, will skip updating firewall if not provided.
--token API token for Cloudflare account
--zone domain zone that you are updating
--hosts list of space delimited hosts to update
--ipv6 Only update IPv6 addresses (default - update both)
--ipv4 Only update IPv4 addresses (default - update both)
--noproxy Do not proxy connections to this host via Cloudflare (basically use CF as DNS provider only). Default - use proxy
```
