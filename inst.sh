#!/bin/bash
(
FQDN="mail.my.dom"
ADMIN_EMAIL="noc@my.dom"
ADMIN_EMAIL_PASSWORD="adminpass"
MYSQL_ROOT_PASSWORD="dbpass"
HORDE_MODE="Webmail & ActiveSync"
SSL_CERT_FILE="/etc/mail/ssl/mail.crt"
SSL_KEY_FILE="/etc/mail/ssl/mail.key"
SSL_CA_CERT_FILE=""

###########################################################
# System
###########################################################

function system_update {
    apt-get update
    apt-get -y install aptitude
###    aptitude -y full-upgrade
}

function system_primary_ip {
    # returns the primary IP assigned to eth0
    #echo $(ifconfig enp1s0 | awk -F: '/inet addr:/ {print $2}' | awk '{ print $1 }')
    ### return ip address assigned to device with default route
    echo $(ip route get 1 | awk '{print $NF;exit}')
}

function get_rdns {
    # calls host on an IP address and returns its reverse dns

    if [ ! -e /usr/bin/host ]; then
        aptitude -y install dnsutils > /dev/null
    fi
    echo $(host $1 | awk '/pointer/ {print $5}' | sed 's/\.$//')
}

function get_rdns_primary_ip {
    # returns the reverse dns of the primary IP assigned to this system
    echo $(get_rdns $(system_primary_ip))
}

function system_set_hostname {
    # $1 - The hostname to define
    HOSTNAME="$1"

    if [ ! -n "$HOSTNAME" ]; then
        echo "Hostname undefined"
        return 1;
    fi
    
    echo "$HOSTNAME" > /etc/hostname
    hostname -F /etc/hostname
}

function system_add_host_entry {
    # $1 - The IP address to set a hosts entry for
    # $2 - The FQDN to set to the IP
    IPADDR="$1"
    DN="$2"

    if [ -z "$IPADDR" -o -z "$DN" ]; then
        echo "IP address and/or FQDN Undefined"
        return 1;
    fi
    
    echo $IPADDR $DN  >> /etc/hosts
}


###########################################################
# Users and Authentication
###########################################################

function user_add_sudo {
    # Installs sudo if needed and creates a user in the sudo group.
    #
    # $1 - Required - username
    # $2 - Required - password
    USERNAME="$1"
    USERPASS="$2"

    if [ ! -n "$USERNAME" ] || [ ! -n "$USERPASS" ]; then
        echo "No new username and/or password entered"
        return 1;
    fi
    
    aptitude -y install sudo
    adduser $USERNAME --disabled-password --gecos ""
    echo "$USERNAME:$USERPASS" | chpasswd
    usermod -aG sudo $USERNAME
}

function user_add_pubkey {
    # Adds the users public key to authorized_keys for the specified user. Make sure you wrap your input variables in double quotes, or the key may not load properly.
    #
    #
    # $1 - Required - username
    # $2 - Required - public key
    USERNAME="$1"
    USERPUBKEY="$2"
    
    if [ ! -n "$USERNAME" ] || [ ! -n "$USERPUBKEY" ]; then
        echo "Must provide a username and the location of a pubkey"
        return 1;
    fi
    
    if [ "$USERNAME" == "root" ]; then
        mkdir /root/.ssh
        echo "$USERPUBKEY" >> /root/.ssh/authorized_keys
        return 1;
    fi
    
    mkdir -p /home/$USERNAME/.ssh
    echo "$USERPUBKEY" >> /home/$USERNAME/.ssh/authorized_keys
    chown -R "$USERNAME":"$USERNAME" /home/$USERNAME/.ssh
}

function ssh_disable_root {
    # Disables root SSH access.
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    touch /tmp/restart-ssh

}

###########################################################
# Postfix
###########################################################

function postfix_install_loopback_only {
    # Installs postfix and configure to listen only on the local interface. Also
    # allows for local mail delivery

    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mailname string localhost" | debconf-set-selections
    echo "postfix postfix/destinations string localhost.localdomain, localhost" | debconf-set-selections
    aptitude -y install postfix
    /usr/sbin/postconf -e "inet_interfaces = loopback-only"
    #/usr/sbin/postconf -e "local_transport = error:local delivery is disabled"

    touch /tmp/restart-postfix
}


###########################################################
# Apache
###########################################################

function apache_install {
    # installs the system default apache2 MPM
    aptitude -y install apache2

    a2dissite default # disable the interfering default virtualhost

    # clean up, or add the NameVirtualHost line to ports.conf
    sed -i -e 's/^NameVirtualHost \*$/NameVirtualHost *:80/' /etc/apache2/ports.conf
    if ! grep -q NameVirtualHost /etc/apache2/ports.conf; then
        echo 'NameVirtualHost *:80' > /etc/apache2/ports.conf.tmp
        cat /etc/apache2/ports.conf >> /etc/apache2/ports.conf.tmp
        mv -f /etc/apache2/ports.conf.tmp /etc/apache2/ports.conf
    fi
}

function apache_tune {
    # Tunes Apache's memory to use the percentage of RAM you specify, defaulting to 40%

    # $1 - the percent of system memory to allocate towards Apache

    if [ ! -n "$1" ];
        then PERCENT=40
        else PERCENT="$1"
    fi

    aptitude -y install apache2-mpm-prefork
    PERPROCMEM=10 # the amount of memory in MB each apache process is likely to utilize
    MEM=$(grep MemTotal /proc/meminfo | awk '{ print int($2/1024) }') # how much memory in MB this system has
    MAXCLIENTS=$((MEM*PERCENT/100/PERPROCMEM)) # calculate MaxClients
    MAXCLIENTS=${MAXCLIENTS/.*} # cast to an integer
    sed -i -e "s/\(^[ \t]*MaxClients[ \t]*\)[0-9]*/\1$MAXCLIENTS/" /etc/apache2/apache2.conf

    touch /tmp/restart-apache2
}

function apache_virtualhost {
    # Configures a VirtualHost

    # $1 - required - the hostname of the virtualhost to create 

    if [ ! -n "$1" ]; then
        echo "apache_virtualhost() requires the hostname as the first argument"
        return 1;
    fi

    if [ -e "/etc/apache2/sites-available/$1" ]; then
        echo /etc/apache2/sites-available/$1 already exists
        return;
    fi

    mkdir -p /srv/www/$1/public_html /srv/www/$1/logs

    echo "<VirtualHost *:80>" > /etc/apache2/sites-available/$1
    echo "    ServerName $1" >> /etc/apache2/sites-available/$1
    echo "    DocumentRoot /srv/www/$1/public_html/" >> /etc/apache2/sites-available/$1
    echo "    ErrorLog /srv/www/$1/logs/error.log" >> /etc/apache2/sites-available/$1
    echo "    CustomLog /srv/www/$1/logs/access.log combined" >> /etc/apache2/sites-available/$1
    echo "</VirtualHost>" >> /etc/apache2/sites-available/$1

    a2ensite $1

    touch /tmp/restart-apache2
}

function apache_virtualhost_from_rdns {
    # Configures a VirtualHost using the rdns of the first IP as the ServerName

    apache_virtualhost $(get_rdns_primary_ip)
}


function apache_virtualhost_get_docroot {
    if [ ! -n "$1" ]; then
        echo "apache_virtualhost_get_docroot() requires the hostname as the first argument"
        return 1;
    fi

    if [ -e /etc/apache2/sites-available/$1 ];
        then echo $(awk '/DocumentRoot/ {print $2}' /etc/apache2/sites-available/$1 )
    fi
}

###########################################################
# mysql-server
###########################################################

function mysql_install {
    # $1 - the mysql root password

    if [ ! -n "$1" ]; then
        echo "mysql_install() requires the root pass as its first argument"
        return 1;
    fi

    echo "mysql-server mysql-server/root_password password $1" | debconf-set-selections
    echo "mysql-server mysql-server/root_password_again password $1" | debconf-set-selections
    apt-get -y install mysql-server mysql-client

    echo "Sleeping while MySQL starts up for the first time..."
    sleep 10
}

function mysql_tune {
    # Tunes MySQL's memory usage to utilize the percentage of memory you specify, defaulting to 40%

    # $1 - the percent of system memory to allocate towards MySQL

    if [ ! -n "$1" ];
        then PERCENT=40
        else PERCENT="$1"
    fi

    sed -i -e 's/^#skip-innodb/skip-innodb/' /etc/mysql/my.cnf # disable innodb - saves about 100M

    MEM=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo) # how much memory in MB this system has
    MYMEM=$((MEM*PERCENT/100)) # how much memory we'd like to tune mysql with
    MYMEMCHUNKS=$((MYMEM/4)) # how many 4MB chunks we have to play with

    # mysql config options we want to set to the percentages in the second list, respectively
    OPTLIST=(key_buffer sort_buffer_size read_buffer_size read_rnd_buffer_size myisam_sort_buffer_size query_cache_size)
    DISTLIST=(75 1 1 1 5 15)

    for opt in ${OPTLIST[@]}; do
        sed -i -e "/\[mysqld\]/,/\[.*\]/s/^$opt/#$opt/" /etc/mysql/my.cnf
    done

    for i in ${!OPTLIST[*]}; do
        val=$(echo | awk "{print int((${DISTLIST[$i]} * $MYMEMCHUNKS/100))*4}")
        if [ $val -lt 4 ]
            then val=4
        fi
        config="${config}\n${OPTLIST[$i]} = ${val}M"
    done

    sed -i -e "s/\(\[mysqld\]\)/\1\n$config\n/" /etc/mysql/my.cnf

    touch /tmp/restart-mysql
}

function mysql_create_database {
    # $1 - the mysql root password
    # $2 - the db name to create

    if [ ! -n "$1" ]; then
        echo "mysql_create_database() requires the root pass as its first argument"
        return 1;
    fi
    if [ ! -n "$2" ]; then
        echo "mysql_create_database() requires the name of the database as the second argument"
        return 1;
    fi

    echo "CREATE DATABASE $2;" | mysql -u root -p$1
}

function mysql_create_user {
    # $1 - the mysql root password
    # $2 - the user to create
    # $3 - their password

    if [ ! -n "$1" ]; then
        echo "mysql_create_user() requires the root pass as its first argument"
        return 1;
    fi
    if [ ! -n "$2" ]; then
        echo "mysql_create_user() requires username as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]; then
        echo "mysql_create_user() requires a password as the third argument"
        return 1;
    fi

    echo "CREATE USER '$2'@'localhost' IDENTIFIED BY '$3';" | mysql -u root -p$1
}

function mysql_grant_user {
    # $1 - the mysql root password
    # $2 - the user to bestow privileges 
    # $3 - the database

    if [ ! -n "$1" ]; then
        echo "mysql_create_user() requires the root pass as its first argument"
        return 1;
    fi
    if [ ! -n "$2" ]; then
        echo "mysql_create_user() requires username as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]; then
        echo "mysql_create_user() requires a database as the third argument"
        return 1;
    fi

    echo "GRANT ALL PRIVILEGES ON $3.* TO '$2'@'localhost';" | mysql -u root -p$1
    echo "FLUSH PRIVILEGES;" | mysql -u root -p$1

}

###########################################################
# PHP functions
###########################################################

function php_install_with_apache {
    aptitude -y install php php-mysql libapache2-mod-php
    touch /tmp/restart-apache2
}

function php_tune {
    # Tunes PHP to utilize up to 32M per process

    sed -i'-orig' 's/memory_limit = [0-9]\+M/memory_limit = 32M/' /etc/php/7.0/apache2/php.ini
    touch /tmp/restart-apache2
}

###########################################################
# Other niceties!
###########################################################

function goodstuff {
    # Installs the REAL vim, wget, less, and enables color root prompt and the "ll" list long alias

    aptitude -y install wget vim less net-tools mc ftp lftp screen bind9utils ntpdate curl screen tcpdump
    sed -i -e 's/^#PS1=/PS1=/' /root/.bashrc # enable the colorful root bash prompt
    sed -i -e "s/^#alias ll='ls -l'/alias ll='ls -al'/" /root/.bashrc # enable ll list long alias <3
}


###########################################################
# utility functions
###########################################################

function restartServices {
    # restarts services that have a file in /tmp/needs-restart/

    for service in $(ls /tmp/restart-* | cut -d- -f2-10); do
        /etc/init.d/$service restart
        rm -f /tmp/restart-$service
    done
}

function randomString {
    if [ ! -n "$1" ];
        then LEN=20
        else LEN="$1"
    fi

    echo $(</dev/urandom tr -dc A-Za-z0-9 | head -c $LEN) # generate a random string
}


function comment_param {
    if [ ! -n "$1" ]
    then
        echo "comment_param() requires the file path as the first argument"
        return 1;
    fi
    if [ ! -n "$2" ]
    then
        echo "comment_param() requires the search term as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]
    then
        REPLACEMENT=$(echo -n $2)
    else
        REPLACEMENT=$(echo -n $3)
    fi
    if [ -n "$4" ] && [[ "$4" == "all" ]]
    then
        /bin/sed -i "s/^[ ]*$2/#$REPLACEMENT/" "$1"
    else
        /bin/sed -i "0,/^[ ]*$2/s//#$REPLACEMENT/" "$1"
    fi
}

function uncomment_param {
    if [ ! -n "$1" ]
    then
        echo "uncomment_param() requires the file path as the first argument"
        return 1;
    fi
    if [ ! -n "$2" ]
    then
        echo "uncomment_param() requires the search term as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]
    then
        REPLACEMENT=$(echo -n $2)
    else
        REPLACEMENT=$(echo -n $3)
    fi
    comment_param "$1" "$2" "$REPLACEMENT" "all"
    if [ -n "$4" ] && [[ "$4" == "all" ]]
    then
        /bin/sed -i "s/^#[#]*[ ]*$2/$REPLACEMENT/" "$1"
    else
        /bin/sed -i "0,/^#[#]*[ ]*$2/s//$REPLACEMENT/" "$1"
    fi
}

function update_param {
    if [ ! -n "$1" ]
    then
        echo "update_param() requires the file path as the first argument"
        return 1;
    fi
    if [ ! -n "$2" ]
    then
        echo "update_param() requires the search term as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]
    then
        echo "update_param() requires the replacement term as the third argument"
        return 1;
    fi
    if [[ $(cat "$1" | grep "^[ ]*$2" | tr -d "\n") == "" ]]
    then
        echo "" >> "$1"
        echo "$3" >> "$1"
    else
        /bin/sed -i "0,/^[ ]*$2\(.*\)/s//$3/" "$1"
    fi
}

function update_param_safe {
    if [ ! -n "$1" ]
    then
        echo "update_param() requires the file path as the first argument"
        return 1;
    fi
    if [ ! -n "$2" ]
    then
        echo "update_param() requires the search term as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]
    then
        echo "update_param() requires the safe (comment) replacement term as the third argument"
        return 1;
    fi
    if [ ! -n "$4" ]
    then
        echo "update_param() requires the replacement term as the third argument"
        return 1;
    fi
    comment_param "$1" "$2" "$3" "all"
    uncomment_param "$1" "$2" "$3"
    update_param "$1" "$2" "$4"
}

function fix_ssl_cert {
    if [ ! -n "$1" ]
    then
        echo "fix_ssl_cert() requires the SSL certificate file as the first argument"
        return 1;
    fi
    
    sed -i "s/\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-/\-\-\-\-\-BEGIN-CERTIFICATE\-\-\-\-\-/g" "$1"
    sed -i "s/\-\-\-\-\-END CERTIFICATE\-\-\-\-\-/\-\-\-\-\-END-CERTIFICATE\-\-\-\-\-/g" "$1"
    sed -i "s/\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-/\-\-\-\-\-BEGIN-RSA-PRIVATE-KEY\-\-\-\-\-/g" "$1"
    sed -i "s/\-\-\-\-\-END RSA PRIVATE KEY\-\-\-\-\-/\-\-\-\-\-END-RSA-PRIVATE-KEY\-\-\-\-\-/g" "$1"
    sed -i "s/ /\n/g" "$1"
    sed -i "s/\-\-\-\-\-BEGIN-CERTIFICATE\-\-\-\-\-/\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-/g" "$1"
    sed -i "s/\-\-\-\-\-END-CERTIFICATE\-\-\-\-\-/\-\-\-\-\-END CERTIFICATE\-\-\-\-\-/g" "$1"
    sed -i "s/\-\-\-\-\-BEGIN-RSA-PRIVATE-KEY\-\-\-\-\-/\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-/g" "$1"
    sed -i "s/\-\-\-\-\-END-RSA-PRIVATE-KEY\-\-\-\-\-/\-\-\-\-\-END RSA PRIVATE KEY\-\-\-\-\-/g" "$1"
}

echo "Updating Installed Packages"
system_update

echo "Installing Extras"
goodstuff

echo "Setting Hostname"
system_set_hostname ${FQDN}

echo "Adding Hostname to /etc/hosts"
system_add_host_entry $(system_primary_ip) "${FQDN}"

if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    echo "SSL support is: ENABLED."
    mkdir -p /opt/ssl
    echo "Setting Up SSL Certificates"
    cat "${SSL_CERT_FILE}" > /opt/ssl/ssl.pem
    cat "${SSL_KEY_FILE}" > /opt/ssl/ssl.key
    fix_ssl_cert /opt/ssl/ssl.pem
    fix_ssl_cert /opt/ssl/ssl.key
    echo "Using Certificate:"
    cat /opt/ssl/ssl.pem
    if [ "$SSL_CA_CERT_FILE" != "" ]
    then
        echo "Setting Up SSL CA Certificate"
        echo "$SSL_CA_CERT_FILE" > /opt/ssl/ca.pem
        fix_ssl_cert /opt/ssl/ca.pem
    fi
else
    echo "SSL support is: DISABLED."
fi

echo "Installing MySQL"
MYSQL_MAIL_PASSWORD=$(LC_CTYPE=C tr -cd 'a-zA-Z0-9' < /dev/urandom | head -c 32)
MYSQL_HORDE_PASSWORD=$(LC_CTYPE=C tr -cd 'a-zA-Z0-9' < /dev/urandom | head -c 32)
mysql_install "$MYSQL_ROOT_PASSWORD"
mysql_tune

echo "Creating MySQL User 'mail' with Password '$MYSQL_MAIL_PASSWORD'"
mysql_create_user "$MYSQL_ROOT_PASSWORD" 'mail' "$MYSQL_MAIL_PASSWORD"

echo "Creating MySQL User 'horde' with Password '$MYSQL_HORDE_PASSWORD'"
mysql_create_user "$MYSQL_ROOT_PASSWORD" 'horde' "$MYSQL_HORDE_PASSWORD"

echo "Creating MySQL Database 'mail'"
mysql_create_database "$MYSQL_ROOT_PASSWORD" "mail"

echo "Creating MySQL Database 'horde'"
mysql_create_database "$MYSQL_ROOT_PASSWORD" "horde"

echo "Granting all Privileges on MySQL Database 'mail' to User 'mail'"
mysql_grant_user "$MYSQL_ROOT_PASSWORD" 'mail' 'mail'

echo "Granting all Privileges on MySQL Database 'horde' to User 'horde'"
mysql_grant_user "$MYSQL_ROOT_PASSWORD" 'horde' 'horde'

echo "Creating MySQL Table 'virtual_domains' on Database 'mail'"
echo "CREATE TABLE mail.virtual_domains (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(50) NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

echo "Creating MySQL Table 'virtual_users' on Database 'mail'"
echo "CREATE TABLE mail.virtual_users (id INT NOT NULL AUTO_INCREMENT, domain_id INT NOT NULL, password VARCHAR(106) NOT NULL, email VARCHAR(120) NOT NULL, PRIMARY KEY (id), UNIQUE KEY email (email), FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8;" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

echo "Creating MySQL Table 'virtual_aliases' on Database 'mail'"
echo "CREATE TABLE mail.virtual_aliases (id INT NOT NULL AUTO_INCREMENT, domain_id INT NOT NULL, source varchar(100) NOT NULL, destination varchar(100) NOT NULL, PRIMARY KEY (id), FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8;" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

echo "Creating MySQL Table 'dkim_keys' on Database 'mail'"
echo "CREATE TABLE mail.dkim_keys (id INT NOT NULL AUTO_INCREMENT, domain_id INT NOT NULL, public_key TEXT, PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

echo "Creating MySQL Table 'admin_users' on Database 'mail'"
echo "CREATE TABLE mail.admin_users (id INT NOT NULL AUTO_INCREMENT, mail_user_id INT NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

echo "Creating MySQL Table 'admin_sessions' on Database 'mail'"
echo "CREATE TABLE mail.admin_sessions (id INT NOT NULL AUTO_INCREMENT, admin_user_id INT NOT NULL, expiry DATETIME NOT NULL, session_cookie VARCHAR(255) NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8;" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

echo "Installing Postfix MTA"
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string ${FQDN}" | debconf-set-selections
echo "postfix postfix/destinations string localhost" | debconf-set-selections
/usr/bin/aptitude -y install postfix postfix-mysql

echo "Configuring Postfix MTA - main.cf"
/usr/sbin/postconf "myhostname = ${FQDN}"
if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    /usr/sbin/postconf "smtpd_tls_cert_file = /opt/ssl/ssl.pem"
    /usr/sbin/postconf "smtpd_tls_key_file = /opt/ssl/ssl.key"
    if [ "$SSL_CA_CERT_FILE" != "" ]
    then
        /usr/sbin/postconf "smtpd_tls_CAfile = /opt/ssl/ca.pem"
    fi
    /usr/sbin/postconf "smtpd_use_tls = yes"
else
    /usr/sbin/postconf "smtpd_use_tls = no"
fi
/usr/sbin/postconf "smtpd_tls_auth_only = no"
/usr/sbin/postconf "smtpd_sasl_type = dovecot"
/usr/sbin/postconf "smtpd_sasl_path = private/auth"
/usr/sbin/postconf "smtpd_sasl_auth_enable = yes"
/usr/sbin/postconf "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"
/usr/sbin/postconf "mydestination = localhost"
/usr/sbin/postconf "virtual_transport = procmail"
/usr/sbin/postconf "virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf"
/usr/sbin/postconf "virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf"
/usr/sbin/postconf "virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf"
/usr/sbin/postconf "milter_protocol = 2"
/usr/sbin/postconf "milter_default_action = accept"
/usr/sbin/postconf "smtpd_milters = inet:localhost:8891"
/usr/sbin/postconf "non_smtpd_milters = inet:localhost:8891"
/usr/sbin/postconf "procmail_destination_recipient_limit = 1"

echo "Configuring Postfix MTA - master.cf"
/usr/sbin/postconf -M "submission/inet=submission inet n - - - - smtpd"
/usr/sbin/postconf -P "submission/inet/syslog_name=postfix/submission"
/usr/sbin/postconf -P "submission/inet/smtpd_tls_security_level=encrypt"
/usr/sbin/postconf -P "submission/inet/smtpd_sasl_auth_enable=yes"
/usr/sbin/postconf -P "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
/usr/sbin/postconf -M "smtp/inet=smtp inet n - - - - smtpd"

if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    /usr/sbin/postconf -M "smtps/inet=smtps inet n - - - - smtpd"
    /usr/sbin/postconf -P "smtps/inet/syslog_name=postfix/smtps"
    /usr/sbin/postconf -P "smtps/inet/smtpd_tls_wrappermode=yes"
    /usr/sbin/postconf -P "smtps/inet/smtpd_sasl_auth_enable=yes"
    /usr/sbin/postconf -P "smtps/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
fi

/usr/sbin/postconf -M "procmail/unix=procmail unix - n n - 10 pipe flags=DORX user=vmail argv=/usr/bin/procmail -tom SENDER=\${sender} USER=\${user}@\${domain} DOMAIN=\${domain} EXTENSION=\${extension} RECIPIENT=\${recipient} /etc/procmailrc"

echo "Configuring Postfix MTA's MySQL Connection"
echo "user = mail" > /etc/postfix/mysql-virtual-mailbox-domains.cf
echo "password = $MYSQL_MAIL_PASSWORD" >> /etc/postfix/mysql-virtual-mailbox-domains.cf
echo "hosts = 127.0.0.1" >> /etc/postfix/mysql-virtual-mailbox-domains.cf
echo "dbname = mail" >> /etc/postfix/mysql-virtual-mailbox-domains.cf
echo "query = SELECT 1 FROM virtual_domains WHERE name='%s'" >> /etc/postfix/mysql-virtual-mailbox-domains.cf

echo "user = mail" > /etc/postfix/mysql-virtual-mailbox-maps.cf
echo "password = $MYSQL_MAIL_PASSWORD" >> /etc/postfix/mysql-virtual-mailbox-maps.cf
echo "hosts = 127.0.0.1" >> /etc/postfix/mysql-virtual-mailbox-maps.cf
echo "dbname = mail" >> /etc/postfix/mysql-virtual-mailbox-maps.cf
echo "query = SELECT 1 FROM virtual_users WHERE email='%s'" >> /etc/postfix/mysql-virtual-mailbox-maps.cf

echo "user = mail" > /etc/postfix/mysql-virtual-alias-maps.cf
echo "password = $MYSQL_MAIL_PASSWORD" >> /etc/postfix/mysql-virtual-alias-maps.cf
echo "hosts = 127.0.0.1" >> /etc/postfix/mysql-virtual-alias-maps.cf
echo "dbname = mail" >> /etc/postfix/mysql-virtual-alias-maps.cf
echo "query = SELECT destination FROM virtual_aliases WHERE source='%s'" >> /etc/postfix/mysql-virtual-alias-maps.cf

echo "Installing Procmail"
/usr/bin/aptitude -y install procmail

echo "Configuring Procmail"
echo "DROPPRIVS=yes" > /etc/procmailrc
echo "LOGFILE=/var/log/procmail.log" >> /etc/procmailrc
echo "VERBOSE=on" >> /etc/procmailrc
echo "SUBJECT=\`formail -xSubject:\`" >> /etc/procmailrc
echo "" >> /etc/procmailrc
echo ":0fw: clamassassin.lock" >> /etc/procmailrc
echo "| /usr/bin/clamassassin" >> /etc/procmailrc
echo "" >> /etc/procmailrc
echo ":0fw: spamassassin.lock" >> /etc/procmailrc
echo "| /usr/bin/spamc" >> /etc/procmailrc
echo "" >> /etc/procmailrc
echo ":0:" >> /etc/procmailrc
echo "* ^X-Virus-Status: Yes" >> /etc/procmailrc
echo "| /usr/bin/formail -i \"Subject: [VIRUS]\$SUBJECT\" | /usr/lib/dovecot/deliver -f \"\$SENDER\" -d \"\$RECIPIENT\" -m \"Spam\"" >> /etc/procmailrc
echo "" >> /etc/procmailrc
echo ":0:" >> /etc/procmailrc
echo "* ^X-Spam-Status: Yes" >> /etc/procmailrc
echo "| /usr/lib/dovecot/deliver -f \"\$SENDER\" -d \"\$RECIPIENT\" -m \"Spam\"" >> /etc/procmailrc
echo "" >> /etc/procmailrc
echo ":0w" >> /etc/procmailrc
echo "| /usr/lib/dovecot/deliver -f \"\$SENDER\" -d \"\$RECIPIENT\"" >> /etc/procmailrc
echo "" >> /etc/procmailrc
echo "EXITCODE=\$?" >> /etc/procmailrc

echo "Creating Procmail Logfile"
touch /var/log/procmail.log
chown root:adm /var/log/procmail.log
chmod 777 /var/log/procmail.log

echo "Installing Dovecot"
echo "dovecot-core dovecot-core/create-ssl-cert boolean false" | debconf-set-selections
/usr/bin/aptitude -y install dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql

echo "Creating Dovecot Maildir: /var/mail/vhosts"
mkdir -p "/var/mail/vhosts/"

echo "Creating 'vmail' User"
groupadd -g 5000 vmail 
useradd -g vmail -u 5000 vmail -d /var/mail

echo "Setting Permissions for Dovecot"
chown -R vmail:vmail /var/mail
chown -R vmail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot 

echo "Configuring Dovecot - dovecot.conf"
uncomment_param /etc/dovecot/dovecot.conf "\!include conf\.d\/\*\.conf"
update_param_safe /etc/dovecot/dovecot.conf "protocols[ ]*=" "protocols =" "protocols = imap lmtp"

echo "Configuring Dovecot - 10-mail.conf"
update_param_safe /etc/dovecot/conf.d/10-mail.conf "mail_location[ ]*=" "mail_location =" "mail_location = maildir\:\/var\/mail\/vhosts\/\%d\/\%n"
update_param_safe /etc/dovecot/conf.d/10-mail.conf "mail_privileged_group[ ]*=" "mail_privileged_group =" "mail_privileged_group = mail"

echo "Configuring Dovecot - 10-auth.conf"
update_param_safe /etc/dovecot/conf.d/10-auth.conf "auth_mechanisms[ ]*=" "auth_mechanisms =" "auth_mechanisms = plain login digest-md5 cram-md5"
if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    update_param_safe /etc/dovecot/conf.d/10-auth.conf "disable_plaintext_auth[ ]*=" "disable_plaintext_auth =" "disable_plaintext_auth = yes"
else
    update_param_safe /etc/dovecot/conf.d/10-auth.conf "disable_plaintext_auth[ ]*=" "disable_plaintext_auth =" "disable_plaintext_auth = no"
fi
comment_param /etc/dovecot/conf.d/10-auth.conf "\!include auth\-system\.conf\.ext" "\!include auth\-system\.conf\.ext" "all"
uncomment_param /etc/dovecot/conf.d/10-auth.conf "\!include auth\-sql\.conf\.ext" "\!include auth\-sql\.conf\.ext"

echo "Configuring Dovecot - 10-master.conf"
echo "service imap-login {" > /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener imap {" >> /etc/dovecot/conf.d/10-master.conf
echo "    port = 143" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener imaps {" >> /etc/dovecot/conf.d/10-master.conf
echo "    port = 993" >> /etc/dovecot/conf.d/10-master.conf
echo "    ssl = yes" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service lmtp {" >> /etc/dovecot/conf.d/10-master.conf
echo "  unix_listener /var/spool/postfix/private/dovecot-lmtp {" >> /etc/dovecot/conf.d/10-master.conf
echo "    mode = 0600" >> /etc/dovecot/conf.d/10-master.conf
echo "    user = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "    group = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service auth {" >> /etc/dovecot/conf.d/10-master.conf
echo "  unix_listener /var/spool/postfix/private/auth {" >> /etc/dovecot/conf.d/10-master.conf
echo "    mode = 0666" >> /etc/dovecot/conf.d/10-master.conf
echo "    user = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "    group = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "  unix_listener auth-userdb {" >> /etc/dovecot/conf.d/10-master.conf
echo "    mode = 0600" >> /etc/dovecot/conf.d/10-master.conf
echo "    user = vmail" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "  user = dovecot" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service auth-worker {" >> /etc/dovecot/conf.d/10-master.conf
echo "  user = vmail" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf

echo "Configuring Dovecot - 10-ssl.conf"
uncomment_param /etc/dovecot/conf.d/10-ssl.conf "ssl[ ]*=" "ssl ="
uncomment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_cert[ ]*=" "ssl_cert ="
uncomment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_key[ ]*=" "ssl_key ="
uncomment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_ca[ ]*=" "ssl_ca ="
update_param_safe /etc/dovecot/conf.d/10-ssl.conf "ssl_cert[ ]*=" "ssl_cert =" "ssl_cert = \<\/opt\/ssl\/ssl\.pem"
update_param_safe /etc/dovecot/conf.d/10-ssl.conf "ssl_key[ ]*=" "ssl_key =" "ssl_key = \<\/opt\/ssl\/ssl\.key"
update_param_safe /etc/dovecot/conf.d/10-ssl.conf "ssl_ca[ ]*=" "ssl_ca =" "ssl_ca = \<\/opt\/ssl\/ca\.pem"
if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    if [ "$SSL_CA_CERT_FILE" == "" ]
    then
        comment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_ca[ ]*=" "ssl_ca ="
    fi
    update_param_safe /etc/dovecot/conf.d/10-ssl.conf "ssl[ ]*=" "ssl =" "ssl = required"
else
    comment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_cert[ ]*=" "ssl_cert ="
    comment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_key[ ]*=" "ssl_key ="
    comment_param /etc/dovecot/conf.d/10-ssl.conf "ssl_ca[ ]*=" "ssl_ca ="
    update_param_safe /etc/dovecot/conf.d/10-ssl.conf "ssl[ ]*=" "ssl =" "ssl = no"
fi

echo "Configuring Dovecot - dovecot-sql.conf.ext"
update_param_safe /etc/dovecot/dovecot-sql.conf.ext "driver[ ]*=" "driver =" "driver = mysql"
update_param_safe /etc/dovecot/dovecot-sql.conf.ext "connect[ ]*=" "connect =" "connect = host=127\.0\.0\.1 dbname=mail user=mail password=$MYSQL_MAIL_PASSWORD"
update_param_safe /etc/dovecot/dovecot-sql.conf.ext "default_pass_scheme[ ]*=" "default_pass_scheme =" "default_pass_scheme = SHA512\-CRYPT"
update_param_safe /etc/dovecot/dovecot-sql.conf.ext "password_query[ ]*=" "password_query =" "password_query = SELECT email as user\, password FROM virtual_users WHERE email=\'\%u\'\;"

echo "Configuring Dovecot - auth-sql.conf.ext"
echo "passdb {" > /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  driver = sql" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  args = /etc/dovecot/dovecot-sql.conf.ext" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "}" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "userdb {" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  driver = static" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "}" >> /etc/dovecot/conf.d/auth-sql.conf.ext

echo "Installing OpenDKIM"
/usr/bin/aptitude -y install opendkim opendkim-tools

echo "Configuring OpenDKIM"
update_param_safe /etc/default/opendkim "SOCKET[ ]*=" "SOCKET=" "SOCKET=\"inet:12301@localhost\""
echo "AutoRestart yes" > /etc/opendkim.conf
echo "AutoRestartRate 10/1h" >> /etc/opendkim.conf
echo "UMask 002" >> /etc/opendkim.conf
echo "Syslog yes" >> /etc/opendkim.conf
echo "SyslogSuccess yes" >> /etc/opendkim.conf
echo "LogWhy yes" >> /etc/opendkim.conf
echo "Canonicalization relaxed/simple" >> /etc/opendkim.conf
echo "ExternalIgnoreList refile:/etc/opendkim/TrustedHosts" >> /etc/opendkim.conf
echo "InternalHosts refile:/etc/opendkim/TrustedHosts" >> /etc/opendkim.conf
echo "KeyTable refile:/etc/opendkim/KeyTable" >> /etc/opendkim.conf
echo "SigningTable refile:/etc/opendkim/SigningTable" >> /etc/opendkim.conf
echo "Mode sv" >> /etc/opendkim.conf
echo "PidFile /var/run/opendkim/opendkim.pid" >> /etc/opendkim.conf
echo "SignatureAlgorithm rsa-sha256" >> /etc/opendkim.conf
echo "UserID opendkim:opendkim" >> /etc/opendkim.conf
echo "Socket inet:8891@localhost" >> /etc/opendkim.conf
/bin/mkdir -p /etc/opendkim
/bin/mkdir -p /opt/dkim
/usr/bin/touch /etc/opendkim/TrustedHosts
/usr/bin/touch /etc/opendkim/KeyTable
/usr/bin/touch /etc/opendkim/SigningTable
echo "127.0.0.1" > /etc/opendkim/TrustedHosts
echo "localhost" >> /etc/opendkim/TrustedHosts
echo "" >> /etc/opendkim/KeyTable
echo "" >> /etc/opendkim/SigningTable

echo "Installing Spamassassin"
/usr/bin/aptitude -y install spamassassin spamc
/usr/sbin/useradd spamd

echo "Configuring Spamassassin (spamassassin)"
#update_param_safe /etc/default/spamassassin "ENABLED=" "ENABLED=" "ENABLED=1"
update_param_safe /etc/default/spamassassin "SPAMD_HOME=" "SPAMD_HOME=" "SPAMD_HOME=\"/home/spamd/\""
update_param_safe /etc/default/spamassassin "OPTIONS=" "OPTIONS=" "OPTIONS=\"--create-prefs --max-children 5 --username spamd --helper-home-dir \${SPAMD_HOME} -s \${SPAMD_HOME}spamd.log\""
update_param_safe /etc/default/spamassassin "PIDFILE=" "PIDFILE=" "PIDFILE=\"\${SPAMD_HOME}spamd.pid\""
update_param_safe /etc/default/spamassassin "CRON=" "CRON=" "CRON=1"

echo "Configuring Spamassassin (local.cf)"
update_param_safe /etc/spamassassin/local.cf "report_safe" "report_safe" "report_safe 0"
update_param_safe /etc/spamassassin/local.cf "required_score" "required_score" "required_score 5\.0"
update_param_safe /etc/spamassassin/local.cf "use_bayes" "use_bayes" "use_bayes 1"
update_param_safe /etc/spamassassin/local.cf "bayes_auto_learn" "bayes_auto_learn" "bayes_auto_learn 1"
update_param_safe /etc/spamassassin/local.cf "skip_rbl_checks" "skip_rbl_checks" "skip_rbl_checks 0"

echo "Starting Spamd"
/etc/init.d/spamassassin start

echo "Installing Clamassassin"
/usr/bin/aptitude -y install clamav-daemon clamav-freshclam clamassassin

echo "Starting Clamassassin Daemon"
/etc/init.d/clamav-daemon start

echo "Installing Apache & PHP"
/usr/bin/aptitude -y install apache2 apache2-utils libapache2-mod-php

echo "Configuring Apache"
if [ "$HORDE_MODE" != "Webmail & ActiveSync" ]
then
    /bin/sed -i "0,/^[ ]*Listen 80\(.*\)/s//Listen 80\nListen 8040\nListen 8080/" /etc/apache2/ports.conf
    mkdir -p /var/www/webmail
    
    echo "<VirtualHost *:80>" > /etc/apache2/sites-available/000-webmail.conf
    echo "    ServerAdmin $ADMIN_EMAIL" >> /etc/apache2/sites-available/000-webmail.conf
    echo "    DocumentRoot /var/www/webmail" >> /etc/apache2/sites-available/000-webmail.conf
    echo "" >> /etc/apache2/sites-available/000-webmail.conf
    echo "    ErrorLog \${APACHE_LOG_DIR}/error.log" >> /etc/apache2/sites-available/000-webmail.conf
    echo "    CustomLog \${APACHE_LOG_DIR}/access.log combined" >> /etc/apache2/sites-available/000-webmail.conf
    echo "" >> /etc/apache2/sites-available/000-webmail.conf
    echo "    Alias /Microsoft-Server-ActiveSync /var/www/horde/rpc.php" >> /etc/apache2/sites-available/000-webmail.conf
    echo "</VirtualHost>" >> /etc/apache2/sites-available/000-webmail.conf

    echo "<VirtualHost *:8040>" > /etc/apache2/sites-available/000-horde.conf
else
    /bin/sed -i "0,/^[ ]*Listen 80\(.*\)/s//Listen 80\nListen 8080/" /etc/apache2/ports.conf

    echo "<VirtualHost *:80>" > /etc/apache2/sites-available/000-horde.conf
fi

echo "    ServerAdmin $ADMIN_EMAIL" >> /etc/apache2/sites-available/000-horde.conf
echo "    DocumentRoot /var/www/horde" >> /etc/apache2/sites-available/000-horde.conf
echo "" >> /etc/apache2/sites-available/000-horde.conf
echo "    ErrorLog \${APACHE_LOG_DIR}/error.log" >> /etc/apache2/sites-available/000-horde.conf
echo "    CustomLog \${APACHE_LOG_DIR}/access.log combined" >> /etc/apache2/sites-available/000-horde.conf
echo "" >> /etc/apache2/sites-available/000-horde.conf
echo "    Alias /Microsoft-Server-ActiveSync /var/www/horde/rpc.php" >> /etc/apache2/sites-available/000-horde.conf
echo "</VirtualHost>" >> /etc/apache2/sites-available/000-horde.conf

if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    echo "" >> /etc/apache2/sites-available/000-horde.conf

    if [ "$HORDE_MODE" != "Webmail & ActiveSync" ]
    then
        /bin/sed -i "s/Listen 443/Listen 443\n        Listen 8042\n        Listen 8082/" /etc/apache2/ports.conf

        echo "<VirtualHost *:443>" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    ServerAdmin $ADMIN_EMAIL" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    DocumentRoot /var/www/webmail" >> /etc/apache2/sites-available/000-webmail.conf
        echo "" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    ErrorLog \${APACHE_LOG_DIR}/error.log" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    CustomLog \${APACHE_LOG_DIR}/access.log combined" >> /etc/apache2/sites-available/000-webmail.conf
        echo "" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    Alias /Microsoft-Server-ActiveSync /var/www/horde/rpc.php" >> /etc/apache2/sites-available/000-webmail.conf
        echo "" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    SSLEngine on" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    SSLCertificateFile /opt/ssl/ssl.pem" >> /etc/apache2/sites-available/000-webmail.conf
        echo "    SSLCertificateKeyFile /opt/ssl/ssl.key" >> /etc/apache2/sites-available/000-webmail.conf
        if [ "$SSL_CA_CERT_FILE" != "" ]
        then
            echo "    SSLCACertificateFile /opt/ssl/ca.pem" >> /etc/apache2/sites-available/000-webmail.conf
        fi
        echo "</VirtualHost>" >> /etc/apache2/sites-available/000-webmail.conf

        echo "<VirtualHost *:8042>" >> /etc/apache2/sites-available/000-horde.conf
    else
        /bin/sed -i "s/Listen 443/Listen 443\n        Listen 8082/" /etc/apache2/ports.conf

        echo "<VirtualHost *:443>" >> /etc/apache2/sites-available/000-horde.conf
    fi

    echo "    ServerAdmin $ADMIN_EMAIL" >> /etc/apache2/sites-available/000-horde.conf
    echo "    DocumentRoot /var/www/horde" >> /etc/apache2/sites-available/000-horde.conf
    echo "" >> /etc/apache2/sites-available/000-horde.conf
    echo "    ErrorLog \${APACHE_LOG_DIR}/error.log" >> /etc/apache2/sites-available/000-horde.conf
    echo "    CustomLog \${APACHE_LOG_DIR}/access.log combined" >> /etc/apache2/sites-available/000-horde.conf
    echo "" >> /etc/apache2/sites-available/000-horde.conf
    echo "    Alias /Microsoft-Server-ActiveSync /var/www/horde/rpc.php" >> /etc/apache2/sites-available/000-horde.conf
    echo "" >> /etc/apache2/sites-available/000-horde.conf
    echo "    SSLEngine on" >> /etc/apache2/sites-available/000-horde.conf
    echo "    SSLCertificateFile /opt/ssl/ssl.pem" >> /etc/apache2/sites-available/000-horde.conf
    echo "    SSLCertificateKeyFile /opt/ssl/ssl.key" >> /etc/apache2/sites-available/000-horde.conf
    if [ "$SSL_CA_CERT_FILE" != "" ]
    then
        echo "    SSLCACertificateFile /opt/ssl/ca.pem" >> /etc/apache2/sites-available/000-horde.conf
    fi
    echo "</VirtualHost>" >> /etc/apache2/sites-available/000-horde.conf

    echo "Enabling mod_ssl for Apache"
    /usr/sbin/a2enmod ssl
fi

echo "Disabling Unused Apache Sites"
/usr/sbin/a2dissite 000-default

echo "Enabling Required Apache Sites"
if [ "$HORDE_MODE" != "Webmail & ActiveSync" ]
then
    /usr/sbin/a2ensite 000-webmail 000-horde
else
    /usr/sbin/a2ensite 000-horde
fi

echo "Configuring PHP"
update_param_safe /etc/php/7.0/apache2/php.ini "session\.gc_divisor" "session\.gc_divisor" "session\.gc_divisor 10000"
update_param_safe /etc/php/7.0/apache2/php.ini "session\.gc_probability" "session\.gc_probability" "session\.gc_probability 1"

echo "Installing PHP Extras"
/usr/bin/aptitude -y install php-dev php-pear php-tidy php-gd php-geoip php-intl php-imagick php-mysql php-memcache php-horde-lz4 php-mcrypt php-mbstring php-bz2 php-curl php-soap php-xmlrpc php-imap

echo "Registering Horde PEAR Channel"
/usr/bin/pear channel-discover pear.horde.org

echo "Adding newer pear modules than those asked by Horde"
/usr/bin/pear channel-update pear.php.net
#/usr/bin/pear install pear/Console_GetoptPlus
/usr/bin/pear install pear/HTTP_Request2
/usr/bin/pear install pear/MDB2
#/usr/bin/pear install pear/Auth_SASL2
/usr/bin/pear install pear/Net_URL2
#/usr/bin/pear install pear/Numbers_Words
#/usr/bin/pear install pear/Image_Text
/usr/bin/pear install horde/Horde_ManageSieve

echo "Preparing Horde Groupware Webmail Edition"
/usr/bin/pear install horde/horde_role
echo "/var/www/horde" | /usr/bin/pear run-scripts horde/horde_role

echo "Installing Horde Groupware Webmail Edition"
echo "(This may take a while)"
/usr/bin/pear install -a -B horde/webmail

echo "Configuring Horde Groupware Webmail Edition"
HORDE_SECRET_KEY=$(php -r "echo sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x', mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0x0fff) | 0x4000, mt_rand(0, 0x3fff) | 0x8000, mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff));")
echo "<?php" > /var/www/horde/config/conf.php
echo "/* CONFIG START. DO NOT CHANGE ANYTHING IN OR AFTER THIS LINE. */" >> /var/www/horde/config/conf.php
echo "\$conf['vhosts'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['debug_level'] = E_ALL & ~E_NOTICE;" >> /var/www/horde/config/conf.php
echo "\$conf['max_exec_time'] = 0;" >> /var/www/horde/config/conf.php
echo "\$conf['compress_pages'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['secret_key'] = '$HORDE_SECRET_KEY';" >> /var/www/horde/config/conf.php
echo "\$conf['umask'] = 077;" >> /var/www/horde/config/conf.php
echo "\$conf['testdisable'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['use_ssl'] = 2;" >> /var/www/horde/config/conf.php
echo "\$conf['server']['name'] = \$_SERVER['SERVER_NAME'] . ':' . \$_SERVER['SERVER_PORT'];" >> /var/www/horde/config/conf.php
echo "\$conf['urls']['token_lifetime'] = 30;" >> /var/www/horde/config/conf.php
echo "\$conf['urls']['hmac_lifetime'] = 30;" >> /var/www/horde/config/conf.php
echo "\$conf['urls']['pretty'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['safe_ips'] = array();" >> /var/www/horde/config/conf.php
echo "\$conf['session']['name'] = 'Horde';" >> /var/www/horde/config/conf.php
echo "\$conf['session']['use_only_cookies'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['session']['timeout'] = 0;" >> /var/www/horde/config/conf.php
echo "\$conf['session']['cache_limiter'] = 'nocache';" >> /var/www/horde/config/conf.php
echo "\$conf['session']['max_time'] = 72000;" >> /var/www/horde/config/conf.php
echo "\$conf['cookie']['domain'] = \$_SERVER['SERVER_NAME'];" >> /var/www/horde/config/conf.php
echo "\$conf['cookie']['path'] = '/';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['username'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['password'] = '$MYSQL_HORDE_PASSWORD';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['hostspec'] = '127.0.0.1';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['port'] = 3306;" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['protocol'] = 'tcp';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['database'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['charset'] = 'utf-8';" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['ssl'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['splitread'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['sql']['phptype'] = 'mysqli';" >> /var/www/horde/config/conf.php
echo "\$conf['nosql']['phptype'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['ldap']['useldap'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['admins'] = array('$ADMIN_EMAIL');" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['checkip'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['checkbrowser'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['resetpassword'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['alternate_login'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['redirect_on_logout'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['list_users'] = 'list';" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['params']['app'] = 'imp';" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['driver'] = 'application';" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['params']['count_bad_logins'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['params']['login_block'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['params']['login_block_count'] = 5;" >> /var/www/horde/config/conf.php
echo "\$conf['auth']['params']['login_block_time'] = 5;" >> /var/www/horde/config/conf.php
echo "\$conf['signup']['allow'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['log']['priority'] = 'INFO';" >> /var/www/horde/config/conf.php
echo "\$conf['log']['ident'] = 'HORDE';" >> /var/www/horde/config/conf.php
echo "\$conf['log']['name'] = LOG_USER;" >> /var/www/horde/config/conf.php
echo "\$conf['log']['type'] = 'syslog';" >> /var/www/horde/config/conf.php
echo "\$conf['log']['enabled'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['log_accesskeys'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['prefs']['maxsize'] = 65535;" >> /var/www/horde/config/conf.php
echo "\$conf['prefs']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['prefs']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['alarms']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['alarms']['params']['ttl'] = 300;" >> /var/www/horde/config/conf.php
echo "\$conf['alarms']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['group']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['group']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['perms']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['perms']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['share']['no_sharing'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['share']['auto_create'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['share']['world'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['share']['any_group'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['share']['hidden'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['share']['cache'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['share']['driver'] = 'Sqlng';" >> /var/www/horde/config/conf.php
echo "\$conf['cache']['default_lifetime'] = 86400;" >> /var/www/horde/config/conf.php
echo "\$conf['cache']['params']['sub'] = 0;" >> /var/www/horde/config/conf.php
echo "\$conf['cache']['driver'] = 'File';" >> /var/www/horde/config/conf.php
echo "\$conf['cache']['use_memorycache'] = '';" >> /var/www/horde/config/conf.php
echo "\$conf['cachecssparams']['url_version_param'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['cachecss'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['cachejsparams']['url_version_param'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['cachejs'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['cachethemes'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['lock']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['lock']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['token']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['token']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['history']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['history']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['davstorage']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['davstorage']['driver'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['mailer']['params']['sendmail_path'] = '/usr/lib/sendmail';" >> /var/www/horde/config/conf.php
echo "\$conf['mailer']['params']['sendmail_args'] = '-oi';" >> /var/www/horde/config/conf.php
echo "\$conf['mailer']['type'] = 'sendmail';" >> /var/www/horde/config/conf.php
echo "\$conf['vfs']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['vfs']['type'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['sessionhandler']['type'] = 'Builtin';" >> /var/www/horde/config/conf.php
echo "\$conf['sessionhandler']['hashtable'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['spell']['driver'] = '';" >> /var/www/horde/config/conf.php
echo "\$conf['gnupg']['keyserver'] = array('pool.sks-keyservers.net');" >> /var/www/horde/config/conf.php
echo "\$conf['gnupg']['timeout'] = 10;" >> /var/www/horde/config/conf.php
echo "\$conf['nobase64_img'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['image']['driver'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['exif']['driver'] = 'Bundled';" >> /var/www/horde/config/conf.php
echo "\$conf['timezone']['location'] = 'ftp://ftp.iana.org/tz/tzdata-latest.tar.gz';" >> /var/www/horde/config/conf.php
echo "\$conf['problems']['email'] = '$ADMIN_EMAIL';" >> /var/www/horde/config/conf.php
echo "\$conf['problems']['maildomain'] = '${FQDN}';" >> /var/www/horde/config/conf.php
echo "\$conf['problems']['tickets'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['problems']['attachments'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['menu']['links']['help'] = 'all';" >> /var/www/horde/config/conf.php
echo "\$conf['menu']['links']['prefs'] = 'authenticated';" >> /var/www/horde/config/conf.php
echo "\$conf['menu']['links']['problem'] = 'all';" >> /var/www/horde/config/conf.php
echo "\$conf['menu']['links']['login'] = 'all';" >> /var/www/horde/config/conf.php
echo "\$conf['menu']['links']['logout'] = 'authenticated';" >> /var/www/horde/config/conf.php
echo "\$conf['portal']['fixed_blocks'] = array();" >> /var/www/horde/config/conf.php
echo "\$conf['accounts']['driver'] = 'null';" >> /var/www/horde/config/conf.php
echo "\$conf['user']['verify_from_addr'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['user']['select_view'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['facebook']['enabled'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['twitter']['enabled'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['urlshortener'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['weather']['provider'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['imap']['enabled'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['imsp']['enabled'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['kolab']['enabled'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['hashtable']['driver'] = 'none';" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['params']['driverconfig'] = 'horde';" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['storage'] = 'Sql';" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['emailsync'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['version'] = '14.1';" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['auth']['type'] = 'basic';" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['autodiscovery'] = 'full';" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['outlookdiscovery'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['logging']['type'] = false;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['ping']['heartbeatmin'] = 60;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['ping']['heartbeatmax'] = 2700;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['ping']['heartbeatdefault'] = 480;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['ping']['deviceping'] = true;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['ping']['waitinterval'] = 15;" >> /var/www/horde/config/conf.php
echo "\$conf['activesync']['enabled'] = true;" >> /var/www/horde/config/conf.php
echo "/* CONFIG END. DO NOT CHANGE ANYTHING IN OR BEFORE THIS LINE. */" >> /var/www/horde/config/conf.php

if [ "$SSL_CERT_FILE" != "" ] && [ "$SSL_KEY_FILE" != "" ]
then
    echo "<?php" > /var/www/horde/imp/config/backends.local.php
    echo "" >> /var/www/horde/imp/config/backends.local.php
    echo "\$servers = array();" >> /var/www/horde/imp/config/backends.local.php
    echo "\$servers['imap'] = array(" >> /var/www/horde/imp/config/backends.local.php
    echo "  'disabled' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "  'name' => 'IMAP Server'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'hostspec' => 'localhost'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'hordeauth' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "  'protocol' => 'imap'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'port' => 993," >> /var/www/horde/imp/config/backends.local.php
    echo "  'secure' => 'ssl'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'smtp' => array(" >> /var/www/horde/imp/config/backends.local.php
    echo "    'auth' => 'true'," >> /var/www/horde/imp/config/backends.local.php
    echo "    'debug' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "    'horde_auth' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "    'host' => 'localhost'," >> /var/www/horde/imp/config/backends.local.php
    echo "    'port' => 465," >> /var/www/horde/imp/config/backends.local.php
    echo "    'secure' => 'ssl'," >> /var/www/horde/imp/config/backends.local.php
    echo "    'username' => null," >> /var/www/horde/imp/config/backends.local.php
    echo "    'password' => null" >> /var/www/horde/imp/config/backends.local.php
    echo "  )," >> /var/www/horde/imp/config/backends.local.php
    echo "  'special_mboxes' => array(" >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_DRAFTS => 'Drafts'," >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_SENT => 'Sent'," >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_SPAM => 'Spam'," >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_TRASH => 'Trash'" >> /var/www/horde/imp/config/backends.local.php
    echo "  )" >> /var/www/horde/imp/config/backends.local.php
    echo ");" >> /var/www/horde/imp/config/backends.local.php
    echo "" >> /var/www/horde/imp/config/backends.local.php
    echo "?>" >> /var/www/horde/imp/config/backends.local.php
else
    echo "<?php" > /var/www/horde/imp/config/backends.local.php
    echo "" >> /var/www/horde/imp/config/backends.local.php
    echo "\$servers = array();" >> /var/www/horde/imp/config/backends.local.php
    echo "\$servers['imap'] = array(" >> /var/www/horde/imp/config/backends.local.php
    echo "  'disabled' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "  'name' => 'IMAP Server'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'hostspec' => 'localhost'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'hordeauth' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "  'protocol' => 'imap'," >> /var/www/horde/imp/config/backends.local.php
    echo "  'port' => 143," >> /var/www/horde/imp/config/backends.local.php
    echo "  'smtp' => array(" >> /var/www/horde/imp/config/backends.local.php
    echo "    'auth' => 'true'," >> /var/www/horde/imp/config/backends.local.php
    echo "    'debug' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "    'horde_auth' => false," >> /var/www/horde/imp/config/backends.local.php
    echo "    'host' => 'localhost'," >> /var/www/horde/imp/config/backends.local.php
    echo "    'port' => 25," >> /var/www/horde/imp/config/backends.local.php
    echo "    'username' => null," >> /var/www/horde/imp/config/backends.local.php
    echo "    'password' => null" >> /var/www/horde/imp/config/backends.local.php
    echo "  )," >> /var/www/horde/imp/config/backends.local.php
    echo "  'special_mboxes' => array(" >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_DRAFTS => 'Drafts'," >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_SENT => 'Sent'," >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_SPAM => 'Spam'," >> /var/www/horde/imp/config/backends.local.php
    echo "    IMP_Mailbox::MBOX_TRASH => 'Trash'" >> /var/www/horde/imp/config/backends.local.php
    echo "  )" >> /var/www/horde/imp/config/backends.local.php
    echo ");" >> /var/www/horde/imp/config/backends.local.php
    echo "" >> /var/www/horde/imp/config/backends.local.php
    echo "?>" >> /var/www/horde/imp/config/backends.local.php
fi

echo "<?php" > /var/www/horde/imp/config/prefs.local.php
echo "\$_prefs['use_trash']['value'] = 1;" >> /var/www/horde/imp/config/prefs.local.php

echo "Configuring Horde Groupware Webmail Edition MySQL"
php <<'EOF'
<?php
$error_level = E_ALL & ~E_STRICT;
if (defined('E_DEPRECATED')) {
    $error_level &= ~E_DEPRECATED;
}
ini_set('error_reporting', $error_level);
ini_set('display_errors', 1);
require_once 'PEAR/Config.php';
require_once PEAR_Config::singleton()->get('horde_dir', null, 'pear.horde.org') . '/lib/Application.php';
$cli = Horde_Core_Cli::init();
if (!$cli->runningFromCLI()) {
    $cli->fatal('This script must be run from the command line.');
}
$cli->writeln();
$cli->writeln($cli->yellow($cli->bold('Installing Horde Groupware Webmail Edition')));
$bundle = new Horde_Bundle($cli);
$bundle->init();
$bundle->migrateDb();
$bundle->writeAllConfigs();
$cli->writeln();
$cli->writeln($cli->yellow($cli->bold('Thank you for using Horde Groupware Webmail Edition!')));
$cli->writeln();
?>
EOF

echo "Setting Correct Web Permissions"
chown -R www-data:www-data /var/www/

echo "Creating Email Account with Address: $ADMIN_EMAIL"
echo "INSERT INTO mail.virtual_domains (id, name) VALUES (1, \"${FQDN}\");" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
echo "INSERT INTO mail.virtual_users (id, domain_id, email, password) VALUES (1, 1, \"$ADMIN_EMAIL\", ENCRYPT(\"$ADMIN_EMAIL_PASSWORD\", CONCAT(\"\$6\$\", SUBSTRING(SHA(RAND()), -16))));" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
echo "INSERT INTO mail.virtual_aliases (id, domain_id, source, destination) VALUES (1, 1, \"$ADMIN_EMAIL\", \"$ADMIN_EMAIL\");" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"
echo "Generating DKIM Key for Email Account with Address: $ADMIN_EMAIL"
MAIL_DKIM_KEY=$(/usr/bin/opendkim-genkey --domain "${FQDN}" --directory=/tmp ; cat /tmp/default.txt | awk -F'"' '{print $2}' | tr -d "\n")
echo "INSERT INTO mail.dkim_keys (id, domain_id, public_key) VALUES (1, 1, \"$MAIL_DKIM_KEY;\");" | mysql -u root -p"$MYSQL_ROOT_PASSWORD"

) > /root/mail_server_install.log 2>&1
echo "Done"
