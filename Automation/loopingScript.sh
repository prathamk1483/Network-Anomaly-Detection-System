#!/bin/bash

while true; do
    # Remove the existing capture file (if it exists)
    rm -f capture.pcap

    # Capture traffic for 5 seconds and save to a new file
    tshark -i Wi-Fi -a duration:5 -w capture.pcap

    # Run the Python script for feature extraction and prediction
    python collectionAndPrediction.py
done
