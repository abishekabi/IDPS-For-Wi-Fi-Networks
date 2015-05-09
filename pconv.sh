#!/bin/sh
echo "=========================PCAP to TXT converter============================"

tshark -nr IDS_Analysis.pcap -T text > IDS_Analysis.txt 

echo "=========================Conversion Successfull==========================="
