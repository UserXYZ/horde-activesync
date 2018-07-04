#!/bin/sh

if [ $# -eq 0 ]; then
    echo "$0 email domain [alias]"
    exit 1
fi

USER=$1
DOM=$2
MYSQL_ROOT_PASSWORD="dbpass"

if [ $# -eq 3 ]; then
    ALIAS=$3
else
    ALIAS=$1
fi

ID=$(echo "SELECT MAX(id) FROM mail.virtual_users" | mysql -N -u root -p"$MYSQL_ROOT_PASSWORD")
ID=$((ID+1))
DID=$(echo "SELECT id FROM mail.virtual_domains WHERE name='$DOM'" | mysql -N -u root -p"$MYSQL_ROOT_PASSWORD")

echo "Creating user $USER in $DOM domain with alias $ALIAS"
echo "INSERT INTO mail.virtual_users (id, domain_id, email, password) VALUES (${ID}, ${DID}, \"$USER\", ENCRYPT(\"password1\", CONCAT(\"\$6\$\", SUBSTRING(SHA(RAND()), -16))));" | mysql -N -u root -p"$MYSQL_ROOT_PASSWORD"
echo "INSERT INTO mail.virtual_aliases (id, domain_id, source, destination) VALUES (${ID}, ${DID}, \"$ALIAS\", \"$USER\");" | mysql -N -u root -p"$MYSQL_ROOT_PASSWORD"
echo "Generating DKIM Key for Email Account with Address: $USER"
MAIL_DKIM_KEY=$(/usr/bin/opendkim-genkey --domain "${USER}" --directory=/tmp ; cat /tmp/default.txt | awk -F'"' '{print $2}' | tr -d "\n")
echo "INSERT INTO mail.dkim_keys (id, domain_id, public_key) VALUES (${ID}, ${DID}, \"$MAIL_DKIM_KEY;\");" | mysql -N -u root -p"$MYSQL_ROOT_PASSWORD"

#echo "Creating Email Account with Address: $USER"
#echo "INSERT INTO mail.virtual_domains (id, name) VALUES (1, \"mail.my.dom\");" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
#echo "INSERT INTO mail.virtual_users (id, domain_id, email, password) VALUES (1, 1, \"$ADMIN_EMAIL\", ENCRYPT(\"$ADMIN_EMAIL_PASSWORD\", CONCAT(\"\$6\$\", SUBSTRING(SHA(RAND()), -16))));" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
#echo "INSERT INTO mail.virtual_aliases (id, domain_id, source, destination) VALUES (1, 1, \"$ADMIN_EMAIL\", \"$ADMIN_EMAIL\");" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
#echo "Generating DKIM Key for Email Account with Address: $USER"
#MAIL_DKIM_KEY=$(/usr/bin/opendkim-genkey --domain "${FQDN}" --directory=/tmp ; cat /tmp/default.txt | awk -F'"' '{print $2}' | tr -d "\n")
#echo "INSERT INTO mail.dkim_keys (id, domain_id, public_key) VALUES (1, 1, \"$MAIL_DKIM_KEY;\");" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
