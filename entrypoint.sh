#!/bin/bash

set -e

EGA_GID=$(getent group lega | awk -F: '{ print $3 }')

cat > /etc/ega/auth.conf <<EOF
#ega_shell = /bin/bash
#ega_uid_shift = 10000

ega_gid = ${EGA_GID}
chroot_sessions = yes
db_path = /run/ega.db
ega_dir = /ega/inbox
ega_dir_attrs = 2750 # rwxr-s---
#ega_dir_umask = 027 # world-denied

######## OpenID Connect
client_id = lega
client_secret = FEc4f9be0F2A9e0EaEd63775eAC1bab8A0dD16d7727C4eABe54FDE3fbabc511C
idp_url = https://idp.ega-archive.org/authorize
redirect_uri = http%3A%2F%2Ftf.crg.eu%3A9090%2Ftokens%2F
EOF

# Changing permissions
echo "Changing permissions for /ega/inbox"
chgrp lega /ega/inbox
chmod 750 /ega/inbox
chmod g+s /ega/inbox # setgid bit

# pip3.6 install git+https://github.com/NBISweden/LocalEGA-cryptor.git
# echo "Starting the FileSystem upload notification server"
# gosu lega ega-notifier &

pip3.6 install PyYaml cryptography aiohttp aiohttp_session aiohttp_jinja2 jinja2
python3.6 /ega/relay.py &

yum install -y libuuid libuuid-devel qrencode-devel qrencode-libs

echo "Starting the SFTP server"
exec /opt/openssh/sbin/ega -D -e -f /etc/ega/sshd_config
