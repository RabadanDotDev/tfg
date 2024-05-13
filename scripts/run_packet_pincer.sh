#!/usr/bin/env bash

cd /workspaces/tfg/packet_pincer
cargo run --release -q -- -c ../tmp/toniot_test.csv offline-analysis      --traces-dir /Datasets/TON-IoT/     |& tee ../tmp/toniot_test.txt
cargo run --release -q -- -c ../tmp/botiot_test.csv offline-analysis      --traces-dir /Datasets/Bot-IoT/     |& tee ../tmp/botiot_test.txt
cargo run --release -q -- -c ../tmp/cicddos2019_test.csv offline-analysis --traces-dir /Datasets/CICDDoS2019/ |& tee ../tmp/cicddos2019_test.txt
