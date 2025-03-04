#!/bin/bash

while true; do
    # Capture traffic for 5 seconds and save to a file
    tshark -i Wi-Fi -a duration:5 -w capture.pcap
    python DSscript.py
    python predictRes.py
done