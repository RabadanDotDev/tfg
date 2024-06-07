#!/usr/bin/env python3

from pathlib import Path
from glob import glob
from datetime import datetime
from typing import List
from natsort import natsorted
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import distinctipy
import functools
import gc
import json

CICDDOS2019_PACKET_PINCER_FILES_GLOB_PATTERN = "/workspaces/tfg/tmp/packet_pincer_CICDDoS2019.*.csv"
BOTIOT_PACKET_PINCER_FILES_GLOB_PATTERN = "/workspaces/tfg/tmp/packet_pincer_BoT-IoT.*.csv"
TONIOT_PACKET_PINCER_FILES_GLOB_PATTERN= "/workspaces/tfg/tmp/packet_pincer_TON-IoT.*.csv"
REPORT_MEDIA_FOLDER = Path("/workspaces/tfg/report/media/")
TMP_FOLDER = Path("/workspaces/tfg/tmp")

PACKET_PINCER_COLUMNS = ["source_ip","source_port","dest_ip","dest_port","transport_protocol","first_packet_time","last_packet_time","duration_seconds","has_tcp","has_udp","bidirectional_packet_count","forward_packet_count","backward_packet_count","bidirectional_packet_second","forward_packet_second","backward_packet_second","bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std","bidirectional_tcp_cwr_flags_count","bidirectional_tcp_ece_flags_count","bidirectional_tcp_urg_flags_count","bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average","label"]
PACKET_PINCER_IDENTIFICATION = ["source_ip","source_port","dest_ip","dest_port","transport_protocol","first_packet_time","last_packet_time"]
PACKET_PINCER_BOOLEAN_VALUES = ["has_tcp","has_udp"]
PACKET_PINCER_CONTINUOUS_VALUES = ["duration_seconds", "bidirectional_packet_count","forward_packet_count","backward_packet_count","bidirectional_packet_second","forward_packet_second","backward_packet_second","bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std","bidirectional_tcp_cwr_flags_count","bidirectional_tcp_ece_flags_count","bidirectional_tcp_urg_flags_count","bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average"]
PACKET_PINCER_LABEL = "label"

def get_files(glob_pattern : str) -> List[str]:
    files = glob(glob_pattern)
    files = natsorted(files)
    return files

def read_csvs(files: List[str]) -> List[pd.DataFrame]:
    print(f"Reading csv files")
    return [pd.read_csv(file) for file in files]

def plot_label_distribution(dfs: List[pd.DataFrame], base_name: str) -> None:
    print(f"Plotting label distribution")
    value_counts = [df[PACKET_PINCER_LABEL].value_counts() for df in dfs]
    value_counts = functools.reduce(lambda a, b: a.add(b, fill_value=0), value_counts)
    value_counts.sort_values()
    num_labels = len(value_counts)
    plt.clf()
    plt.bar(
        x      = np.arange(0, num_labels),
        height = value_counts.values, 
        label  = value_counts.index, 
        color  = distinctipy.get_colors(num_labels, pastel_factor=0.7)
    )
    plt.xticks(
        ticks = np.arange(0, num_labels),
        labels = value_counts.index,
        rotation='vertical'
    )
    plt.yscale('log')
    plt.ylabel('Número de flujos')
    plt.ylim(bottom=1)
    path = REPORT_MEDIA_FOLDER / base_name / 'labels.png'; path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(path, bbox_inches="tight")

    counts = {}
    for tag,count in zip(value_counts.index, value_counts.values):
        counts[tag] = int(count)
    with open(TMP_FOLDER / f'{base_name}_labels_count.json', 'w') as f:
        f.write(json.dumps(counts))

def plot_boolean_values(dfs: List[pd.DataFrame], base_name: str) -> None:
    print(f"Plotting boolean values")
    boolean_values = [] 
    boolean_counts = {}
    
    for boolean_value in PACKET_PINCER_BOOLEAN_VALUES:
        v = sum([df[boolean_value].sum() for df in dfs])
        boolean_values.append(v)
        boolean_counts[boolean_value] = int(v)

    num_labels = len(boolean_values)
    plt.clf()
    plt.bar(
        x      = np.arange(0, num_labels),
        height = boolean_values, 
        label  = PACKET_PINCER_BOOLEAN_VALUES, 
        color  = distinctipy.get_colors(num_labels, pastel_factor=0.7)
    )
    plt.xticks(
        ticks = np.arange(0, num_labels),
        labels = PACKET_PINCER_BOOLEAN_VALUES,
        rotation = 'vertical'
    )
    plt.yscale('log')
    plt.ylabel('Número de flujos')
    plt.ylim(bottom=1)
    path = REPORT_MEDIA_FOLDER / base_name / f'boolean_values.png'; path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(path, bbox_inches="tight")

    with open(TMP_FOLDER / f'{base_name}_boolean_counts.json', 'w') as f:
        f.write(json.dumps(boolean_counts))

def plot_continuous_values(dfs: List[pd.DataFrame], base_name: str) -> None:
    print(f"Plotting continuous values")
    number_of_zeroes = {}

    for feature in PACKET_PINCER_CONTINUOUS_VALUES:
        gc.collect()
        print(f"Plotting continuous values {feature}")

        # Get values
        values = pd.concat([df[feature] for df in dfs])
        number_of_zeroes["total_count"] = len(values)
        number_of_zeroes[feature] = int((values == 0).sum())
        gc.collect()

        # Plot linearx/logy
        plt.clf()
        plt.hist(values, bins=60)
        plt.ylabel('Número de flujos')
        plt.xlabel(f"{feature}")
        plt.yscale('log')
        plt.ylim(bottom=1)
        path = REPORT_MEDIA_FOLDER / base_name / f'{feature}_linear_x_log_y.png'; path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(path, bbox_inches="tight")

        # log(+1) values
        values = np.log(pd.Series(values) + 1)
        gc.collect()

        # Plot logx/logy
        plt.clf()
        plt.hist(values, bins=60)
        plt.ylabel('Número de flujos')
        plt.xlabel(f"{feature} (log + 1)")
        plt.yscale('log')
        plt.ylim(bottom=1)
        path = REPORT_MEDIA_FOLDER / base_name / f'{feature}_log_x_log_y.png'; path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(path, bbox_inches="tight")

    with open(TMP_FOLDER / f'{base_name}_continuous_zeroes.json', 'w') as f:
        f.write(json.dumps(number_of_zeroes))
    
def analyze(glob_pattern: str, base_name: str) -> None:
    print(f"Analyzing {base_name}")
    dfs = read_csvs(get_files(glob_pattern))
    gc.collect()
    plot_label_distribution(dfs, base_name)
    gc.collect()
    plot_boolean_values(dfs, base_name)
    gc.collect()
    plot_continuous_values(dfs, base_name)
    gc.collect()

def main() -> None:
    analyze(BOTIOT_PACKET_PINCER_FILES_GLOB_PATTERN, "packet_pincer_botiot")
    analyze(TONIOT_PACKET_PINCER_FILES_GLOB_PATTERN, "packet_pincer_toniot")
    analyze(CICDDOS2019_PACKET_PINCER_FILES_GLOB_PATTERN, "packet_pincer_cicddos")

if __name__=="__main__":
    main()
