#!/usr/bin/env bash

cd /workspaces/tfg/packet_pincer

# Run for CICDDoS2019
cargo run --release -- -c ../tmp/packet_pincer_CICDDoS2019.csv -g ../tmp/CICDDoS2019_gt.csv offline-analysis --traces-dir /Datasets/CICDDoS2019/pcap/

# Run for TON-IoT
# ..

# Run for BoT-IoT
# ..
