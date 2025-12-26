#!/bin/bash
set -xe
current_time=$(date +"%B %d, %Y %H:%M:%S")
echo "Current Time : $current_time"

# Stop the proxy service
systemctl stop wstunnel
systemctl stop haproxy

# Wait for 3 minutes
sleep 180

# Start the proxy service
systemctl start haproxy
systemctl start wstunnel
