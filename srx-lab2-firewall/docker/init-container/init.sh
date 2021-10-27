#!/usr/bin/env sh
# Initialize container depending on its hostname.

# hostnames
HN_FIREWALL=Firewall
HN_DMZ=ServerInDMZ
HN_LAN=ClientInLAN

HN=`hostname`

if [ $HN = $HN_FIREWALL ]
then
    # enable internet access for lan and dmz machines
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ./init-container/firewall-rules.sh
fi

if [ $HN = $HN_DMZ ]
then
    # remove default route and create new one to go through firewall only
    ip route del default
    ip route add default via 192.168.200.2

    # start nginx
    echo Welcome to the DMZ website > /var/www/html/index.html
    service nginx start
fi

if [ $HN = $HN_FIREWALL ] || [ $HN = $HN_DMZ ]
then
    # permit root login with password – avoid in real life
    sed -Ei 's/^#(PermitRootLogin).*/\1 yes/' /etc/ssh/sshd_config

    # set root password – secure stuff :)
    echo root:root | chpasswd

    # start ssh
    service ssh start
fi

if [ $HN = $HN_LAN ]
then
    # remove default route and create new one to go through firewall only
    ip route del default
    ip route add default via 192.168.100.2
fi

# start shell to keep container running
/bin/sh
