#!/bin/bash

# Define source and destination IP addresses and Interface
source_ip="172.31.0.2"
destination_ip="172.31.0.3"
interface="eth0"

# Send a gratuitous message from Alice to Bob
arping -i "eth0" -c 1 -U -S "$source_ip" "$destination_ip" &> /dev/null

# Send a gratuitous message from Bob to Alice
arping -i "eth0" -c 1 -U -S "$destination_ip" "$source_ip" &> /dev/null