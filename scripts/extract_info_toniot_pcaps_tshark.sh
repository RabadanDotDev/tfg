#!/usr/bin/env bash

FOLDER="/Datasets/TON-IoT/Raw_datasets/network_data/Network_dataset_pcaps/"
FOLDER_RESULTS_FOLDER="./tmp/toniot"

function analyze_pcap_folder {
    mkdir -p $2

    for pcap in $(find $1 -type f | sort)
    do
        echo "Generating conversations csv for $pcap"
        file=$(basename "$pcap")
        file="$2/$file.conv.csv"
        echo "ip origin, ip dest, frames_to_origin, bytes_to_origin, frames_to_dest, bytes_to_dest, frames_total, bytes_total, relative_start, duration" > $file
        tshark -q -z conv,ip -r "$pcap" | tail -n +6 | head -n -1 | tr -d "<>\-," | tr -s " " | awk '{ print $1 ", " $2 ", " $3 ", " $4 " " $5 ", " $6 ", " $7 " " $8 ", " $9 ", " $10 " " $11 ", " $12 ", " $13}' >> $file
    done

    for pcap in $(find $1 -type f | sort -V)
    do
        file=$(basename "$pcap")
        file="$2/$file.treeproto.txt"
        echo "Generating full tree protocols txt $pcap"

        tshark -q -z io,phs -r "$pcap" > $file
    done

    for pcap in $(find $1 -type f | sort -V)
    do
        file=$(basename "$pcap")
        file="$2/$file.ipproto.txt"
        echo "Generating stats ipv4 protocols protocols txt of $pcap"

        tshark -q -z ptype,tree -r "$pcap" > $file
    done
}

analyze_pcap_folder $FOLDER $FOLDER_RESULTS_FOLDER
