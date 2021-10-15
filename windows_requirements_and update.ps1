Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
chocolatey install python3 --fore --y
refreshenv
pip install -r requirements.txt
refreshenv

#Edit this line to match your settings
python cf_dynamic --un fw_un --pw fw_pw --fw 192.168.1.1 --rule test_address --token cf_api_token --email cf_email.com --zone mydomain.com --hosts host1 host2 --ipv6 
