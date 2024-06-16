#!/usr/bin/env bash

cd /workspaces/tfg/packet_pincer

rm -f /workspaces/tfg/tmp/packet_pincer*.csv

# Run for CICDDoS2019
echo "CICDDoS2019"
time cargo run -q --release -- -c /workspaces/tfg/tmp/packet_pincer_CICDDoS2019.csv -g /workspaces/tfg/tmp/CICDDoS2019_gt.csv offline-analysis --traces-dir /Datasets/CICDDoS2019/pcap/

# Run for TON-IoT
echo "TON-IoT"
time cargo run -q --release -- -c /workspaces/tfg/tmp/packet_pincer_TON-IoT.csv -g /workspaces/tfg/tmp/TON-IoT_gt.csv offline-analysis --traces-dir /Datasets/TON-IoT/Raw_datasets/network_data/Network_dataset_pcaps/

# Run for BoT-IoT
echo "BoT-IoT"
time cargo run -q --release -- -c /workspaces/tfg/tmp/packet_pincer_BoT-IoT.csv -g /workspaces/tfg/tmp/BoT-IoT_gt.csv offline-analysis --traces-dir /Datasets/Bot-IoT/PCAPs/
