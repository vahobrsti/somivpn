#!/bin/bash

# Add your existing script content here

# Detect the main network interface
main_interface=$(ip route | awk '/default/ { print $5 }')

# Add the iptables rule for openvpn and opencpnnect
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$main_interface" -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$main_interface" -j MASQUERADE

# Additional commands if needed

echo "iptables rule added successfully."