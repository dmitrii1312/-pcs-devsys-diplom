## Процесс установки и настройки ufw
```
$ sudo ufw allow 22/tcp
Rules updated
Rules updated (v6)
$ sudo ufw allow 443/tcp
Rules updated
Rules updated (v6)
$ sudo ufw allow in on lo
Rule added
Rule added (v6)
$ sudo ufw enable
Command may disrupt existing ssh connections. Proceed with operation (y|n)? y
Firewall is active and enabled on system startup
$ sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
Anywhere on lo             ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
443/tcp (v6)               ALLOW       Anywhere (v6)
Anywhere (v6) on lo        ALLOW       Anywhere (v6)
```

## Процесс установки и выпуска сертификата с помощью hashicorp vault

```
$ sudo apt install jq
$ curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
OK
```
```
$ sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
Hit:1 http://archive.ubuntu.com/ubuntu focal InRelease
Get:2 http://security.ubuntu.com/ubuntu focal-security InRelease [114 kB]
Get:3 https://apt.releases.hashicorp.com focal InRelease [9,495 B]
Get:4 http://archive.ubuntu.com/ubuntu focal-updates InRelease [114 kB]
Hit:5 http://archive.ubuntu.com/ubuntu focal-backports InRelease
Get:6 http://archive.ubuntu.com/ubuntu focal-updates/main i386 Packages [580 kB]
Get:7 https://apt.releases.hashicorp.com focal/main amd64 Packages [41.1 kB]
Get:8 http://archive.ubuntu.com/ubuntu focal-updates/main amd64 Packages [1,434 kB]
Get:9 http://archive.ubuntu.com/ubuntu focal-updates/universe i386 Packages [655 kB]
Get:10 http://archive.ubuntu.com/ubuntu focal-updates/universe amd64 Packages [885 kB]
Fetched 3,832 kB in 1s (3,262 kB/s)
Reading package lists... Done
```
```
$ sudo apt-get update && sudo apt-get install vault
Hit:1 https://apt.releases.hashicorp.com focal InRelease
Hit:2 http://archive.ubuntu.com/ubuntu focal InRelease
Hit:3 http://archive.ubuntu.com/ubuntu focal-updates InRelease
Hit:4 http://archive.ubuntu.com/ubuntu focal-backports InRelease
Get:5 http://security.ubuntu.com/ubuntu focal-security InRelease [114 kB]
Fetched 114 kB in 1s (138 kB/s)
Reading package lists... Done
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages were automatically installed and are no longer required:
  linux-image-unsigned-5.4.0-26-generic linux-modules-5.4.0-26-generic shim
Use 'sudo apt autoremove' to remove them.
The following NEW packages will be installed:
  vault
0 upgraded, 1 newly installed, 0 to remove and 7 not upgraded.
Need to get 69.4 MB of archives.
After this operation, 188 MB of additional disk space will be used.
Get:1 https://apt.releases.hashicorp.com focal/main amd64 vault amd64 1.9.2 [69.4 MB]
Fetched 69.4 MB in 3s (26.9 MB/s)
Selecting previously unselected package vault.
(Reading database ... 49689 files and directories currently installed.)
Preparing to unpack .../archives/vault_1.9.2_amd64.deb ...
Unpacking vault (1.9.2) ...
Setting up vault (1.9.2) ...
Generating Vault TLS key and self-signed certificate...
Generating a RSA private key
...............++++
...................++++
writing new private key to 'tls.key'
-----
Vault TLS key and self-signed certificate have been generated in '/opt/vault/tls'.
```
```
$ vi /etc/vault.d/vault.hcl
```
```
ui = true
storage "file" {
  path = "/opt/vault/data"
}
# HTTP listener
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
```
```
$ sudo systemctl enable vault
$ sudo systemctl start vault
$ export VAULT_ADDR=http://127.0.0.1:8200
```
```
$ vault operator init
Unseal Key 1: sLGLOX0A2nhoWdWsGyV2yPlUk4Kg3EO5H37gKxefAm4a
Unseal Key 2: q+N6nidUBVhFSjw99tiZ6C3s4SYcGDMM+CdvEa+vCklO
Unseal Key 3: ei5ZIjbT1P+QDHqrn0eb2pN/Mp3r9LBKKqkK5Lsr819o
Unseal Key 4: YXyohWyHC9+9H5M6crp0+kfHQDlXMMD/zfCF3gMb+3g8
Unseal Key 5: kgb/zUMxI2PNWYg/+BunTYe7KrRaxjOCJsWC8HgID/b8

Initial Root Token: s.gQdRbL11wZGDFQnaZilk7InH
```
```
$ sudo vi /usr/local/sbin/unseal.sh
#!/bin/bash
source /etc/default/unseal
vault operator unseal sLGLOX0A2nhoWdWsGyV2yPlUk4Kg3EO5H37gKxefAm4a
vault operator unseal q+N6nidUBVhFSjw99tiZ6C3s4SYcGDMM+CdvEa+vCklO
vault operator unseal ei5ZIjbT1P+QDHqrn0eb2pN/Mp3r9LBKKqkK5Lsr819o
```
```
$ sudo vi /etc/default/unseal
export VAULT_ADDR=http://127.0.0.1:8200
```
```
$ sudo vi /etc/systemd/system/unseal.service
[Unit]
Description=Unseal vault
After=vault.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/unseal.sh

[Install]
WantedBy=multi-user.target
```
```
$ sudo systemctl daemon-reload
$ sudo systemctl start unseal
$ export VAULT_TOKEN=s.gQdRbL11wZGDFQnaZilk7InH
$ vault secrets enable pki
Success! Enabled the pki secrets engine at: pki/
$ vault secrets tune -max-lease-ttl=87600h pki
Success! Tuned the secrets engine at: pki/
$ vault write -field=certificate pki/root/generate/internal common_name="example.com" ttl=87600h > CA.crt
$ vault write pki/config/urls issuing_certificates="http://192.168.22.104:8200/v1/pki/ca" crl_distribution_points="http://192.168.22.104:8200/v1/pki/crl"
Success! Data written to: pki/config/urls
$ vault secrets enable -path=pki_int pki
Success! Enabled the pki secrets engine at: pki_int/
$ vault secrets tune -max-lease-ttl=43800h pki_int
Success! Tuned the secrets engine at: pki_int/
$ vault write -format=json pki_int/intermediate/generate/internal common_name="example.com Intermediate Authority" | jq -r '.data.csr' > pki_intermediate.csr
$ vault write -format=json pki/root/sign-intermediate csr=@pki_intermediate.csr format=pem_bundle ttl="43800h" | jq -r '.data.certificate' > intermediate.cert.pem
$ vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem
Success! Data written to: pki_int/intermediate/set-signed
$ vault write pki_int/roles/example-dot-com allowed_domains="example.com" allow_subdomains=true max_ttl="744h"
Success! Data written to: pki_int/roles/example-dot-com
$ vault write -format=json pki_int/issue/example-dot-com common_name="nginx.example.com" ttl="744h" > cert.json
```

## Процесс установки и настройки сервера nginx

```
$ sudo apt install nginx
$ sudo vi /etc/nginx/sites-available/ssl.conf
server {
       listen       443 ssl http2 default_server;
       server_name  nginx.example.com;
       root         /var/www/html;

       ssl_certificate "/etc/nginx/ssl/cert.pem";
       ssl_certificate_key "/etc/nginx/ssl/key.pem";
}
$ sudo mkdir /etc/nginx/ssl
$ cat cert.json | jq -r '.data.private_key' > key.pem
$ cat cert.json | jq -r '.data.certificate' > cert.pem
$ cat cert.json | jq -r '.data.issuing_ca' >> cert.pem
$ sudo cp key.pem /etc/nginx/ssl
$ sudo cp cert.pem /etc/nginx/ssl
$ sudo ln -s /etc/nginx/sites-available/ssl.conf /etc/nginx/sites-enabled
$ sudo systemctl start nginx
$ sudo systemctl enable nginx
```

## Страница сервера nginx в браузере хоста не содержит предупреждений

![image](https://user-images.githubusercontent.com/93075740/148146164-10f8642e-4ff7-4944-a896-189c82a22f83.png)

## Скрипт генерации нового сертификата работает

``` 
# vi /usr/local/sbin/certrenew.sh
```
```
#!/bin/bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=s.gQdRbL11wZGDFQnaZilk7InH
vault write -format=json pki_int/issue/example-dot-com common_name="nginx.example.com" ttl="744h" > /tmp/cert.json
cat /tmp/cert.json | jq -r '.data.private_key' > /etc/nginx/ssl/key.pem
cat /tmp/cert.json | jq -r '.data.certificate' > /etc/nginx/ssl/cert.pem
cat /tmp/cert.json | jq -r '.data.issuing_ca' >> /etc/nginx/ssl/cert.pem
systemctl restart nginx
```
## Crontab работает

```
# tail /var/log/syslog
Jan  5 01:40:01 ubuntu-20 CRON[5599]: (root) CMD (/usr/local/sbin/certrenew.sh)
Jan  5 01:40:02 ubuntu-20 systemd[1]: Stopping A high performance web server and a reverse proxy server...
Jan  5 01:40:02 ubuntu-20 systemd[1]: nginx.service: Succeeded.
Jan  5 01:40:02 ubuntu-20 systemd[1]: Stopped A high performance web server and a reverse proxy server.
Jan  5 01:40:02 ubuntu-20 systemd[1]: Starting A high performance web server and a reverse proxy server...
Jan  5 01:40:02 ubuntu-20 systemd[1]: Started A high performance web server and a reverse proxy server.
```
```
# crontab -e
40 1 5 * * /usr/local/sbin/certrenew.sh
```
