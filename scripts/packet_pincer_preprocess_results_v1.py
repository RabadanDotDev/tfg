#!/usr/bin/env python3

from pathlib import Path
from glob import glob
from datetime import datetime
from typing import List, Tuple
import joblib
from natsort import natsorted
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import distinctipy
import functools
import gc
import json
import sklearn
import sklearn.model_selection
from sklearn.preprocessing import MinMaxScaler
import sklearn.utils
from sklearn.ensemble import RandomForestClassifier
from boruta import BorutaPy

CICDDOS2019_PACKET_PINCER_FILES_GLOB_PATTERN = "/workspaces/tfg/tmp/packet_pincer_CICDDoS2019.*.csv"
BOTIOT_PACKET_PINCER_FILES_GLOB_PATTERN = "/workspaces/tfg/tmp/packet_pincer_BoT-IoT.*.csv"
TONIOT_PACKET_PINCER_FILES_GLOB_PATTERN= "/workspaces/tfg/tmp/packet_pincer_TON-IoT.*.csv"
REPORT_MEDIA_FOLDER = Path("/workspaces/tfg/report/media/")
TMP_FOLDER = Path("/workspaces/tfg/tmp")

PACKET_PINCER_COLUMNS = ["source_ip","source_port","dest_ip","dest_port","transport_protocol","first_packet_time","last_packet_time","duration_seconds","has_tcp","has_udp","bidirectional_packet_count","forward_packet_count","backward_packet_count","bidirectional_packet_second","forward_packet_second","backward_packet_second","bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std","bidirectional_tcp_cwr_flags_count","bidirectional_tcp_ece_flags_count","bidirectional_tcp_urg_flags_count","bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average","label"]
PACKET_PINCER_IDENTIFICATION = ["source_ip","source_port","dest_ip","dest_port","transport_protocol","first_packet_time","last_packet_time"]
PACKET_PINCER_BOOLEAN_VALUES = ["has_tcp","has_udp"]
PACKET_PINCER_CONTINUOUS_VALUES_LOG = ["duration_seconds", "bidirectional_packet_count","forward_packet_count","backward_packet_count",                                                                               "bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std",                                                                                                            "bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average"]
PACKET_PINCER_CONTINUOUS_VALUES     = ["duration_seconds", "bidirectional_packet_count","forward_packet_count","backward_packet_count","bidirectional_packet_second","forward_packet_second","backward_packet_second","bidirectional_packet_bytes_sum","bidirectional_packet_bytes_max","bidirectional_packet_bytes_min","bidirectional_packet_bytes_mean","bidirectional_packet_bytes_std","forward_packet_bytes_sum","forward_packet_bytes_max","forward_packet_bytes_min","forward_packet_bytes_mean","forward_packet_bytes_std","backward_packet_bytes_sum","backward_packet_bytes_max","backward_packet_bytes_min","backward_packet_bytes_mean","backward_packet_bytes_std","bidirectional_bytes_s","forward_bytes_s","backward_bytes_s","down_up_bytes_ratio","bidirectional_inter_arrival_time_max","bidirectional_inter_arrival_time_min","bidirectional_inter_arrival_time_mean","bidirectional_inter_arrival_time_std","forward_inter_arrival_time_max","forward_inter_arrival_time_min","forward_inter_arrival_time_mean","forward_inter_arrival_time_std","backward_inter_arrival_time_max","backward_inter_arrival_time_min","backward_inter_arrival_time_mean","backward_inter_arrival_time_std","bidirectional_tcp_cwr_flags_count","bidirectional_tcp_ece_flags_count","bidirectional_tcp_urg_flags_count","bidirectional_tcp_ack_flags_count","bidirectional_tcp_psh_flags_count","bidirectional_tcp_rst_flags_count","bidirectional_tcp_syn_flags_count","bidirectional_tcp_fin_flags_count","forward_tcp_psh_flags_count","forward_tcp_urg_flags_count","backward_tcp_psh_flags_count","backward_tcp_urg_flags_count","forward_transport_header_bytes_sum","forward_transport_payload_bytes_mean","forward_transport_payload_bytes_min","forward_transport_packets_with_payload_count","forward_tcp_initial_window_bytes","backward_transport_header_bytes_sum","backward_transport_payload_bytes_mean","backward_tcp_initial_window_bytes","idle_seconds_min","idle_seconds_max","idle_seconds_mean","idle_seconds_std","active_seconds_min","active_seconds_max","active_seconds_mean","active_seconds_std","active_group_forward_packet_average","active_group_backward_packet_average","active_group_forward_byte_average","active_group_backward_byte_average","active_group_forward_byte_second_average","active_group_backward_byte_second_average"]
PACKET_PINCER_LABEL = "label"

SAMPLING_PERCENTAGE=0.15/100
TEST_PERCENTAGE=20/100
K_FOLD_SPLITS=5

def remap_labels(df: pd.DataFrame) -> pd.DataFrame:
    mappings = {
        "benign" : 'benign',
        "ddos_dns" : 'malign',
        "ddos_ldap" : 'malign',
        "ddos_mssql" : 'malign',
        "ddos_netbios" : 'malign',
        "ddos_ntp" : 'malign',
        "ddos_snmp" : 'malign',
        "ddos_ssdp" : 'malign',
        "ddos_udp" : 'malign',
        "ddos_ldap" : 'malign',
        "ddos_mssql" : 'malign',
        "ddos_netbios" : 'malign',
        "ddos_portmap" : 'malign',
        "ddos_syn" : 'malign',
        "ddos_tftp" : 'malign',
        "ddos_udp" : 'malign',
        "ddos_udp_lag" : 'malign',
        "ddos_udp_lag" : 'malign',
        "backdoor" : 'malign',
        "ddos" : 'malign',
        "dos" : 'malign',
        "injection" : 'malign',
        "mitm" : 'malign',
        "password" : 'malign',
        "ransomware" : 'malign',
        "scanning" : 'malign',
        "xss" : 'malign',
        "ddos_http" : 'malign',
        "ddos_tcp" : 'malign',
        "ddos_udp" : 'malign',
        "dos_http" : 'malign',
        "dos_tcp" : 'malign',
        "dos_udp" : 'malign',
        "reconnaissance_os_fingerprint" : 'malign',
        "reconnaissance_service_scan" : 'malign',
        "theft_data_exfiltration" : 'malign',
        "theft_keylogging" : 'malign',
    }

    df['label'] = df['label'].replace(mappings)

    return df

def get_files(glob_pattern : str) -> List[str]:
    files = glob(glob_pattern)
    files = natsorted(files)
    return files

def read_csvs_and_sample(files: List[str]) -> pd.DataFrame:
    dfs = []
    for idx,file in enumerate(files):
        gc.collect()
        print(f">({idx+1}/{len(files)}) Reading csv file {file}")
        df = pd.read_csv(file)
        print(f">({idx+1}/{len(files)}) Sampling")
        df = sklearn.utils.resample(df, n_samples=int(len(df)*SAMPLING_PERCENTAGE), random_state=5, stratify=df[PACKET_PINCER_LABEL])
        print(f">({idx+1}/{len(files)}) Discarding id columns")
        df = df.drop(columns=PACKET_PINCER_IDENTIFICATION)
        print(f">({idx+1}/{len(files)}) Dropping unknowns")
        df = df[df['label'] != 'unknown']
        print(f">({idx+1}/{len(files)}) Reasigning labels")
        df = remap_labels(df)
        gc.collect()
        dfs.append(df)
    return pd.concat(dfs)

def split_data(df) -> Tuple[pd.DataFrame, pd.DataFrame, sklearn.model_selection.StratifiedKFold]:
    # Make main train/validation split
    df_train, df_test = sklearn.model_selection.train_test_split(\
        df,
        random_state=5,\
        test_size=TEST_PERCENTAGE,\
        stratify=df[PACKET_PINCER_LABEL]\
    )

    # Prepare kfold
    skf = sklearn.model_selection.StratifiedKFold(n_splits=K_FOLD_SPLITS, shuffle=True, random_state=5)
    
    return (df_train, df_test, skf)

def preprocess_data(df_train, df_test) -> Tuple[pd.DataFrame, pd.DataFrame, MinMaxScaler]:
    print(f">Appling the logarithm+1")
    for feature in PACKET_PINCER_CONTINUOUS_VALUES_LOG:
        df_train[feature] = np.log(df_train[feature] + 1)
        df_test[feature] = np.log(df_test[feature] + 1)

    print(f">Minmax scaling")
    scaler = MinMaxScaler()
    scaler.fit(df_train[PACKET_PINCER_CONTINUOUS_VALUES])
    df_train[PACKET_PINCER_CONTINUOUS_VALUES] = scaler.transform(df_train[PACKET_PINCER_CONTINUOUS_VALUES])
    df_test[PACKET_PINCER_CONTINUOUS_VALUES] = scaler.transform(df_test[PACKET_PINCER_CONTINUOUS_VALUES])
    
    return (df_train, df_test, scaler)

def apply_boruta_selection(df_train) -> np.ndarray:
    # Re-add depcreated values to not downgrade NumPy version
    np.int = np.int32
    np.float = np.float64
    np.bool = np.bool_
    
    # Prepare data
    X = df_train.loc[:, df_train.columns != PACKET_PINCER_LABEL].values
    y = df_train.loc[:, df_train.columns == PACKET_PINCER_LABEL].values.ravel()

    # Execute boruta
    rf = RandomForestClassifier(n_jobs=-1, class_weight='balanced', max_depth=7)
    feat_selector = BorutaPy(rf, n_estimators='auto', verbose=2, random_state=1)
    feat_selector.fit(X, y)

    # Selected columns
    selected = np.append(feat_selector.support_, True)

    print(f">Confirmed: {list(df_train.columns[selected])}")
    print(f">Tentative/rejected: {list(df_train.columns[~selected])}")

    return selected

def main() -> None:
    print("Reading files:")
    df = read_csvs_and_sample(
        get_files(BOTIOT_PACKET_PINCER_FILES_GLOB_PATTERN) +
        get_files(TONIOT_PACKET_PINCER_FILES_GLOB_PATTERN) + 
        get_files(CICDDOS2019_PACKET_PINCER_FILES_GLOB_PATTERN)
    )

    print("Labels:")
    print(df[PACKET_PINCER_LABEL].value_counts())

    df_train, df_test, skf = split_data(df)
    del df; gc.collect()

    print("Labels train:")
    print(df_train[PACKET_PINCER_LABEL].value_counts())

    print("Labels validation:")
    print(df_test[PACKET_PINCER_LABEL].value_counts())

    print("Preprocessing data")
    df_train, df_test, scaler = preprocess_data(df_train, df_test)
    gc.collect()

    print("Applying boruta")
    selected_columns = apply_boruta_selection(df_train)

    print("Storing results")
    df_train.to_csv(TMP_FOLDER / "train_non_selected.csv", index=False)
    df_test.to_csv(TMP_FOLDER / "test_non_selected.csv", index=False)
    df_train.loc[:, list(selected_columns)].to_csv(TMP_FOLDER / "train.csv", index=False)
    df_test.loc[:, list(selected_columns)].to_csv(TMP_FOLDER / "test.csv", index=False)
    joblib.dump(scaler, TMP_FOLDER / "scaler.joblib")
    joblib.dump(skf, TMP_FOLDER / "kfold.joblib")
    
if __name__=="__main__":
    main()
