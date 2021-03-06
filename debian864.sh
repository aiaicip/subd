#!/bin/bash


echo -e "\e[33mAUTOSCRIPT BY CyCloneVPN Solution
Preparing 1st stage before installation begin\e[0m"
echo ""
echo ""
echo ""

apt-get update;
apt-get -y upgrade;
apt-get -y install wget curl;


myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
curl -s -o ip.txt https://raw.githubusercontent.com/aiaicip/thv/master/ip.txt
find=`grep $myip ip.txt`
if ["$find" = ""]
then
clear
echo -e "
              AUTO SCRIPT BY  CyCloneVPN
            [ \e[35mYOUR IP ARE NOT REGISTERED\e[0m ]
              A  U  T  O  -  E  X  I  T 
            ------------------------------
	    FOR REGISTER, CONTACT ADMIN :- 
        [ TELEGRAM : \e[34mhttps://t.me/TogaSinki\e[0m ]
 "
echo -e "\e[33m
  ____       ____ _                __     ______  _   _ 
 / ____   _ / ___| | ___  _ __   __\ \   / |  _ \| \ | |
| |  | | | | |   | |/ _ \| '_ \ / _ \ \ / /| |_) |  \| |
| |__| |_| | |___| | (_) | | | |  __/\ V / |  __/| |\  |
 \____\__, |\____|_|\___/|_| |_|\___| \_/  |_|   |_| \_|
      |___/                                             
\e[0m"
 
rm -f /root/ip.txt
rm -f /root/d864.sh
exit
fi
if [ $USER != 'root' ]; then
	echo "Sorry, for run the script please using root user"
	exit
fi
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP is not available"
	exit
fi
echo "
AUTOSCRIPT BY CyCloneVPN Solution

PLEASE CANCEL ALL PACKAGE POPUP

TAKE NOTE !!!"
clear
echo "START AUTOSCRIPT"
clear

#set time zone malaysia
echo "SET TIMEZONE KUALA LUMPUT GMT +8"
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime;
clear
echo "

ENABLE IPV4 AND IPV6

COMPLETE 1%
"
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear



echo "
REMOVE SPAM PACKAGE

COMPLETE 5%
"
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove postfix*;
apt-get -y --purge remove bind*;
clear
echo "
UPDATE AND UPGRADE PROCESS

"
sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt-get -y autoremove

echo "
INSTALL COMMANDS
COMPLETE 18%
"
#get ip address
apt-get -y install aptitude curl;

if [ "$IP" = "" ]; then
        IP=$(curl -s ifconfig.co)
fi

#install menu
wget https://www.dropbox.com/s/9lgg4nr3f25hiua/menu
wget https://www.dropbox.com/s/arvt35d3i3h6n83/user-list
wget https://www.dropbox.com/s/u8ns6vxz778oi4w/monssh
wget https://www.dropbox.com/s/8db4yzcixp4vcdl/status
mv menu /usr/local/bin/
mv user-list /usr/local/bin/
mv monssh /usr/local/bin/
mv status /usr/local/bin/
chmod +x  /usr/local/bin/menu
chmod +x  /usr/local/bin/user-list
chmod +x  /usr/local/bin/monssh
chmod +x  /usr/local/bin/status
cd

#motd
echo -e "\e[33m

  ____       ____ _                __     ______  _   _ 
 / ____   _ / ___| | ___  _ __   __\ \   / |  _ \| \ | |
| |  | | | | |   | |/ _ \| '_ \ / _ \ \ / /| |_) |  \| |
| |__| |_| | |___| | (_) | | | |  __/\ V / |  __/| |\  |
 \____\__, |\____|_|\___/|_| |_|\___| \_/  |_|   |_| \_|
      |___/                                             

   ================================================
   #                                              #
   #      WELCOME TO CyCloneVPN VPS SYSTEM !      #
   #      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~       #
   #            Telegram : @TogaSinki             #
   #   Copyright © CyCloneVPN Premium VPN™ 2017   #
   #                  by abangG                   #
   #     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~      #
   #     PLEASE TYPE 'menu' FOR EACH MISSION      #
   #                                              #
   ================================================
\e[0m" > /etc/motd
 
# fail2ban & exim & protection
apt-get -y install fail2ban sysv-rc-conf dnsutils dsniff zip unzip;
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip;unzip master.zip;
cd ddos-deflate-master && ./install.sh
service exim4 stop;sysv-rc-conf exim4 off 

# install webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf

#ssh banner
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
wget -O /etc/issue.net "https://www.dropbox.com/s/z2z51cf068qnm2w/banner"

#install dropbear
apt-get -y install dropbear
wget -O /etc/default/dropbear "https://www.dropbox.com/s/zyxl2pi0fw35f7a/dropbear"
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

#installing squid3
aptitude -y install squid3
rm -f /etc/squid3/squid.conf
#restoring squid config with open port proxy 60000 & 8080
wget -P /etc/squid3/ "https://www.dropbox.com/s/86y22kwa1cyytjw/squid.conf"
sed -i "s/ipserver/$IP/g" /etc/squid3/squid.conf
cd

#STunnel
apt-get install stunnel4 -y
wget -P /etc/stunnel/ "https://www.dropbox.com/s/qy017wsbexwg1gm/stunnel.conf"
openssl genrsa -out key.pem 2048
wget -P /etc/stunnel/ "https://www.dropbox.com/s/mssa7cm0y5u6xqv/stunnel.pem"
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart
clear

# Openvpn
apt-get --force-yes -y install openvpn
cd /etc/openvpn/
wget https://www.dropbox.com/s/fndscnoaink2ksm/openvpn.tar;tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/iptables.up.rules "https://www.dropbox.com/s/gkkuku41dvwt10c/iptables.up.rules"
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i "s/ipserver/$IP/g" /etc/iptables.up.rules
iptables-restore < /etc/iptables.up.rules

# Badvpn
echo "#!/bin/bash
if [ "'$1'" == start ]
then
badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 > /dev/null &
echo 'Badvpn Run On Port 7300'
fi
if [ "'$1'" == stop ]
then
badvpnpid="'$(ps x |grep badvpn |grep -v grep |awk '"{'"'print $1'"'})
kill -9 "'"$badvpnpid" >/dev/null 2>/dev/null
kill $badvpnpid > /dev/null 2> /dev/null
kill "$badvpnpid" > /dev/null 2>/dev/null''
kill $(ps x |grep badvpn |grep -v grep |awk '"{'"'print $1'"'})
killall badvpn-udpgw
fi" > /bin/badvpn
chmod +x /bin/badvpn
if [ -f /usr/local/bin/badvpn-udpgw ]; then
echo -e "\033[1;32mBadvpn Installing\033[0m"
exit
else
clear
fi
if [ -f /usr/bin/badvpn-udpgw ]; then
echo -e "\033[1;32mBadvpn Installing\033[0m"
exit
else
clear
fi
echo -e "\033[1;31m           Installing Badvpn\n\033[1;37mInstalling gcc Cmake make g++ openssl etc...\033[0m"
apt-get update >/dev/null 2>/dev/null
apt-get install -y gcc >/dev/null 2>/dev/null
apt-get install -y make >/dev/null 2>/dev/null
apt-get install -y g++ >/dev/null 2>/dev/null
apt-get install -y openssl >/dev/null 2>/dev/null
apt-get install -y build-essential >/dev/null 2>/dev/null
apt-get install -y cmake >/dev/null 2>/dev/null
echo -e "\033[1;37mDownloading File Badvpn"; cd
wget https://www.dropbox.com/s/jat1ttcnqekh6dt/badvpn-1.999.128.tar.bz2 -o /dev/null
echo -e "Extract Badvpn"
tar -xf badvpn-1.999.128.tar.bz2
echo -e "Setup configuration"
mkdir /etc/badvpn-install
cd /etc/badvpn-install
cmake ~/badvpn-1.999.128 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>/dev/null
echo -e "Compile Badvpn\033[0m"
make install
sed -i '$ i\badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/nul &' /etc/rc.local
clear
echo -e "\033[1;32m             Installation Complete\033[0m" 
echo -e "\033[1;37mCommand:\n\033[1;31mbadvpn start\033[1;37m Run Badvpn Service"
echo -e "\033[1;31mbadvpn stop \033[1;37m Stop Badvpn Service\033[0m"
rm -rf /etc/badvpn-install
cd ; rm -rf badvpn.sh badvpn-1.999.128/ badvpn-1.999.128.tar.bz2 >/dev/null 2>/dev/null

#bonus block torrent
wget https://www.dropbox.com/s/gx9dg40eu8smsbg/torrent.sh
chmod +x  torrent.sh
./torrent.sh

#swap ram
wget https://www.dropbox.com/s/0jue4hmhxti08ik/swap-ram.sh
chmod +x  swap-ram.sh
./swap-ram.sh

clear

echo "
COMPLETE 95%

Restart Services
"

# restart service
badvpn start
service ssh restart
service openvpn restart
service dropbear restart
service webmin restart
service squid3 restart
service fail2ban restart
service stunnel4 restart
cd

echo "
COMPLETE 100%
NICE MUAHCHIKED
DONE.
"

echo "BY CyClone VPN"
echo "Webmin      : http://$IP:10000"
echo "OpenSSH     : 22"
echo "Dropbear    : 443"
echo "OpenVPN     : 1194 TCP"
echo "STunnel     : 3128 SSL/TLS"
echo "BadVPN      : 7300 UDPGW"
echo "Proxy Port  : 60000 & 8080"
echo "Ovpn Config : https://t.me/TogaSinki"
echo "Fail2Ban    : [ON]"  
echo "AntiDDOS    : [ON]"  
echo "AntiTorrent : [ON]" 
echo "Login VPS via Putty/Connect Bot/Juice SSH and type menu"
echo "THANK YOU"
echo "BYE"
echo "============================"
echo "PLEASE REBOOT TO TAKE EFFECT"
echo "============================"
echo "TYPE reboot THEN ENTER "
cat /dev/null > ~/.bash_history && history -c
rm -f /root/debian864.sh
