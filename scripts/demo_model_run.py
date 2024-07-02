#!/usr/bin/env python3

from pathlib import Path
import numpy as np
import pandas as pd
import fileinput
import joblib
from io import StringIO

PACKET_PINCER_COLUMNS = ["source_ip","source_port","dest_ip","dest_port","transport_protocol","first_packet_time","last_packet_time","duration_seconds","has_tcp","has_udp","bidirectional_packet_count","forward_packet_count","backward_packet_count","bidirectional_packet_second","forward_packet_second","backward_packet_second","bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std","bidirectional_tcp_cwr_flags_count","bidirectional_tcp_ece_flags_count","bidirectional_tcp_urg_flags_count","bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average","label"]
PACKET_PINCER_IDENTIFICATION = ["source_ip","source_port","dest_ip","dest_port","transport_protocol","first_packet_time","last_packet_time"]
PACKET_PINCER_BOOLEAN_VALUES = ["has_tcp","has_udp"]
PACKET_PINCER_CONTINUOUS_VALUES_LOG = ["duration_seconds", "bidirectional_packet_count","forward_packet_count","backward_packet_count",                                                                               "bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std",                                                                                                            "bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average"]
PACKET_PINCER_CONTINUOUS_VALUES     = ["duration_seconds", "bidirectional_packet_count","forward_packet_count","backward_packet_count","bidirectional_packet_second","forward_packet_second","backward_packet_second","bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std","bidirectional_tcp_cwr_flags_count","bidirectional_tcp_ece_flags_count","bidirectional_tcp_urg_flags_count","bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average"]
PACKET_PINCER_LABEL = "label"
REJECTED_BORUTA_LABELS = ['bidirectional_tcp_cwr_flags_count', 'bidirectional_tcp_ece_flags_count', 'bidirectional_tcp_urg_flags_count']

SCALER = joblib.load('./tmp/scaler.joblib')
MODEL  = joblib.load('./tmp/model.joblib')

def process_line(line):
    # Convert to df
    df = pd.read_csv(StringIO(line.strip()), header=None, names=PACKET_PINCER_COLUMNS)
    source_ip, source_port = df.source_ip[0], df.source_port[0]
    dest_ip, dest_port = df.dest_ip[0], df.dest_port[0]

    # Discard id column
    df = df.drop(columns=PACKET_PINCER_IDENTIFICATION)

    # Apply logarithm+1
    for feature in PACKET_PINCER_CONTINUOUS_VALUES_LOG:
      df[feature] = np.log(df[feature] + 1)

    # Minmax scale
    df[PACKET_PINCER_CONTINUOUS_VALUES] = SCALER.transform(df[PACKET_PINCER_CONTINUOUS_VALUES])

    # Skip boruta ignored and label
    df = df.loc[:, ~df.columns.isin(REJECTED_BORUTA_LABELS + [PACKET_PINCER_LABEL])]

    # Apply model
    prediction = MODEL.predict(df)[0]

    # Print result
    print(f"{prediction} - {source_ip}[:{source_port}] -> {dest_ip}[:{dest_port}]")

def main():
    for line in fileinput.input():
        process_line(line)

if __name__ == "__main__":
    main()
