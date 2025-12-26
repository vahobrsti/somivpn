#!/bin/bash
iptables -F
iptables -P FORWARD ACCEPT
# Print the iptables rule to allow established and related TCP connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Get a comma-separated list of all TCP ports that are currently open and store them in a variable.
open_ports=$(netstat -ntlp | awk 'NR > 2 && $6 == "LISTEN" && $4 !~ /127\.0\.0\.*/ { split($4, a, ":"); printf "%s\n", a[length(a)] }' | sort -u | tr '\n' ',' | sed 's/,$//')
# Get a comma-separated list of all CIDR ranges for the interfaces with a global scope
cidr_ranges=$(ip -o -f inet addr show | awk '/scope global/ {split($4, a, " "); printf "%s\n", a[1]}' | tr '\n' ',' | sed 's/,$//')
iptables -A INPUT -p tcp -m multiport --dports $open_ports -j ACCEPT
iptables -A INPUT -s $cidr_ranges -j ACCEPT
# add localhost
iptables -A INPUT -s 127.0.0.1/8 -j ACCEPT
# a final rule that drops any other incoming TCP connections
iptables -A INPUT -p tcp -j DROP
iptables -A INPUT -p udp -j DROP

