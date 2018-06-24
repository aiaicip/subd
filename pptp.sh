#!/bin/bash

echo "###################################"
echo "This script will configure PPTP VPN"
echo "###################################"

# Install PPTP daemon service
apt-get -y install pptpd

# Set DNS
echo "ms-dns 8.8.8.8" >> /etc/ppp/pptpd-options
echo "ms-dns 8.8.4.4" >> /etc/ppp/pptpd-options

# Get server IP
apt-get -y install wget || {
  echo "Could not install wget, required to retrieve your IP address." 
  exit 1
}

# Find out external ip 
IP=wget -q -O - http://api.ipify.org

if [ "x$IP" = "x" ]
then
  echo "============================================================"
  echo "  !!!  COULD NOT DETECT SERVER EXTERNAL IP ADDRESS  !!!"
else
  echo "============================================================"
  echo "Detected your server external ip address: $IP"
fi

# Set IP for server & user
echo "localip $IP" >> /etc/pptpd.conf
echo "remoteip 10.1.0.100-199" >> /etc/pptpd.conf

# Create User and Random Password
LEN=$(echo ${#PASS})

if [ -z "$PASS" ] || [ $LEN -lt 8 ] || [ -z "$NAME"]
then
   P1=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyz | head -c 4`
   P2=`cat /dev/urandom | tr -cd 0123456789 | head -c 4`
      PASS="$P1$P2"
fi

if [ -z "$NAME" ]
then
   NAME="vpn"
fi

cat >/etc/ppp/chap-secrets <<END
# Secrets for authentication using CHAP
# client server secret IP addresses
$NAME pptpd $PASS *
END


# Forward packet between localip and remoteip
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# Restart sysctl to reload config
sysctl -p

# Allow PPTP traffic on iptables
iptables -P FORWARD ACCEPT
iptables --table nat -A POSTROUTING -o venet0 -j MASQUERADE

# Save iptable
iptables-save

# Auto reload iptables
cat >> /etc/network/if-pre-up.d/iptablesload << END
#!/bin/sh
iptables-restore < /etc/iptables.up.rules
exit 0

END
sh /etc/network/if-pre-up.d/iptablesload

#Execute iptables
chmod +x /etc/network/if-pre-up.d/iptablesload


# User details
echo   "Server       =$IP"
echo   "VPN username = $NAME"
echo   "password     = $PASS"
echo   "============================================================"
sleep 2

# Restart PPTPD to reload all config
service pptpd restart

exit 0
