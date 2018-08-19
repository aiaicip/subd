#!/bin/bash
# Created by CYCLONE VPN

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi
# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";

# install squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
http_port 3128
dns_v4_first on
cache deny all
forwarded_for delete
tcp_outgoing_address xxxxxxxxx 
via off
auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwords
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
END
sed -i $MYIP2 /etc/squid3/squid.conf;

# Setup the password store
apt-get -y install apache2-utils
touch /etc/squid3/passwords
chmod 777 /etc/squid3/passwords
echo "Username  : elite"
echo "Proxy Port: 3128"
echo "Type Your Password"
echo "Pls Remember Your Password" 
htpasswd -c /etc/squid3/passwords elite
#prompt password enter manual

#restart service
service squid3 restart
