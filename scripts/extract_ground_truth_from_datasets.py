from pathlib import Path
from glob import glob
from datetime import datetime
from natsort import natsorted
import numpy as np
import pandas as pd

CICDDOS_2019_CSVS_PATH = Path('/Datasets/CICDDoS2019/csv/')
CICDDOS_2019_CSVS_PATH_RES = Path("./tmp/CICDDoS2019_gt.csv")
BOT_IOT_CSVS_PATH = Path("/Datasets/Bot-IoT/Dataset/Entire Dataset/")
BOT_IOT_FEATURE_NAMES = Path("/Datasets/Bot-IoT/Dataset/Entire Dataset/UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv")
BOT_IOT_PATH_RES = Path("./tmp/BoT-IoT_gt.csv")
TON_IOT_CSVS_PATH = Path('/Datasets/TON-IoT/Processed_datasets/Processed_Network_dataset/')
TON_IOT_CSVS_PATH_RES = Path("./tmp/TON-IoT_gt.csv")

def test_combine_discard():
    df = pd.DataFrame({
        'source_ip'             : ["0.0.0.1", "0.0.0.1", "0.0.0.1", "0.0.0.1", "0.0.0.1"],
        'dest_ip'               : ["0.0.0.2", "0.0.0.2", "0.0.0.3", "0.0.0.2", "0.0.0.2"],
        'timestamp_micro_start' : [        0,        2,          7,         8,        12],
        'timestamp_micro_end'   : [        1,        3,         10,        11,        21],
        'label'                 : [      'a',      'a',        'a',       'b',       'a']
    })

    df_res = pd.DataFrame({
        'source_ip'             : ["0.0.0.1", "0.0.0.1", "0.0.0.1"],
        'dest_ip'               : ["0.0.0.2", "0.0.0.3", "0.0.0.2"],
        'timestamp_micro_start' : [        0,         7,        12],
        'timestamp_micro_end'   : [        3,        10,        21],
        'label'                 : [      'a',       'a',       'a']
    })

    df = combine(df, 'b').sort_values('timestamp_micro_start', ignore_index=True)

    assert df.equals(df_res)

def remap_labels(df: pd.DataFrame) -> pd.DataFrame:
    mappings = {
        # cicddos
        "BENIGN"                        : "benign",
        "DrDoS_DNS"                     : "ddos_dns",
        "DrDoS_LDAP"                    : "ddos_ldap",
        "DrDoS_MSSQL"                   : "ddos_mssql",
        "DrDoS_NetBIOS"                 : "ddos_netbios",
        "DrDoS_NTP"                     : "ddos_ntp",
        "DrDoS_SNMP"                    : "ddos_snmp",
        "DrDoS_SSDP"                    : "ddos_ssdp",
        "DrDoS_UDP"                     : "ddos_udp",
        "LDAP"                          : "ddos_ldap",
        "MSSQL"                         : "ddos_mssql",
        "NetBIOS"                       : "ddos_netbios",
        "Portmap"                       : "ddos_portmap",
        "Syn"                           : "ddos_syn",
        "TFTP"                          : "ddos_tftp",
        "UDP"                           : "ddos_udp",
        "UDP-lag"                       : "ddos_udp_lag",
        "UDPLag"                        : "ddos_udp_lag",
        "WebDDoS"                       : "benign",
        # toniot
        "normal"                        : "benign",
        "backdoor"                      : "backdoor",
        "ddos"                          : "ddos",
        "dos"                           : "dos",
        "injection"                     : "injection",
        "mitm"                          : "mitm",
        "password"                      : "password",
        "ransomware"                    : "ransomware",
        "scanning"                      : "scanning",
        "xss"                           : "xss",
        # botiot
        "Normal_Normal"                 : "benign",
        "DDoS_HTTP"                     : "ddos_http",
        "DDoS_TCP"                      : "ddos_tcp",
        "DDoS_UDP"                      : "ddos_udp",
        "DoS_HTTP"                      : "dos_http",
        "DoS_TCP"                       : "dos_tcp",
        "DoS_UDP"                       : "dos_udp",
        "Reconnaissance_OS_Fingerprint" : "reconnaissance_os_fingerprint",
        "Reconnaissance_Service_Scan"   : "reconnaissance_service_scan",
        "Theft_Data_Exfiltration"       : "theft_data_exfiltration",
        "Theft_Keylogging"              : "theft_keylogging",
    }

    df['label'] = df['label'].replace(mappings)

    return df

def combine(df: pd.DataFrame):
    # Determine groups of labels that can be merged
    df['group_within_ip_pair'] = df\
        .groupby(by=['low_ip', 'high_ip'])\
        .label\
        .transform(
            lambda x: (x != x.shift()).cumsum() - 1
        )

    # Group values and take the min/max timestamps
    df = df.groupby(by=['low_ip', 'high_ip', 'group_within_ip_pair']).agg(
        timestamp_micro_start=('timestamp_micro_start', 'min'),
        timestamp_micro_end=('timestamp_micro_end', 'max'),
        label=('label', 'first')
    ).reset_index().drop(columns=["group_within_ip_pair"])

    return df

def force_remove_overlaps(df: pd.DataFrame) -> pd.DataFrame:
    # Find overlapping consecutive rows
    overlaps_with_previous = (df.timestamp_micro_start <= df.timestamp_micro_end.shift(1)   ) & (df.low_ip == df.low_ip.shift( 1)) & (df.high_ip == df.high_ip.shift( 1))
    overlaps_with_next     = (df.timestamp_micro_end   >= df.timestamp_micro_start.shift(-1)) & (df.low_ip == df.low_ip.shift(-1)) & (df.high_ip == df.high_ip.shift(-1))
    
    # Set overlaps in the middle of the overlap
    df['timestamp_micro_start_og'] = df['timestamp_micro_start']
    df['timestamp_micro_end_og'] = df['timestamp_micro_end']

    df.loc[overlaps_with_previous, 'timestamp_micro_start'] = ((df.timestamp_micro_start_og + df.timestamp_micro_end_og.shift(1)) // 2 + 1)[overlaps_with_previous]
    df.loc[overlaps_with_next, 'timestamp_micro_end'] = ((df.timestamp_micro_end_og + df.timestamp_micro_start_og.shift(-1)) // 2)[overlaps_with_next]

    #del df['timestamp_micro_end_og']
    #del df['timestamp_micro_end_og']

    df['overlaps_with_previous'] = overlaps_with_previous
    df['overlaps_with_next'] = overlaps_with_next

    return df

def extract(name, get_dataframe, result_path):
    # Load values
    print(f"Loading {name} files")
    df: pd.DataFrame = get_dataframe()

    # Remap labels
    print(f"Remapping labels")
    df = remap_labels(df)

    # Set order on src/dst IP addresses
    print(f"Reordering addresses")

    min_ip = np.minimum(df['source_ip'], df['dest_ip'])
    max_ip = np.maximum(df['source_ip'], df['dest_ip'])
    df['source_ip'] = min_ip
    df['dest_ip'] = max_ip

    df = df.rename(columns={
        "source_ip": "low_ip",
        "dest_ip": "high_ip",
    })

    # Sort 
    print(f"Sorting values")
    df = df.sort_values(by=['timestamp_micro_start', 'timestamp_micro_end'], ignore_index=True)

    # Discard the benign tags
    print(f"Discarding benign values")
    df = df.drop(df[df.label == 'benign'].index).reset_index(drop=True)

    # Combine values
    print(f"Combining non benign values")
    df = combine(df)

    # Remove overlaps if there are any remaining
    print(f"Force removing overlaps")
    df = force_remove_overlaps(df)

    # Store results
    df.to_csv(result_path, index=False)

def get_dataframes_cicddos_2019() -> pd.DataFrame:
    dataframes = []
    files = glob(str(CICDDOS_2019_CSVS_PATH / "**/*.csv"))
    files = natsorted(files)

    for idx,file in enumerate(files):
        # Read dataframe
        print(f"{idx+1}/{len(files)} - Loading {file}")
        df = pd.read_csv(file, low_memory=False)

        # Keep only relevant columns
        df = df[[" Source IP", " Destination IP", " Timestamp", " Flow Duration", " Label"]]

        # Rename columns
        df = df.rename(columns={\
            ' Source IP': 'source_ip',\
            ' Destination IP': 'dest_ip',\
            ' Timestamp': 'timestamp_micro_start',\
            ' Flow Duration': 'duration',\
            ' Label': 'label',\
        })

        # Convert timestamp to unix time
                
        # The first value in csvs/03-11/Portmap.csv is 09:18:16.964447 
        # The second packet in pcap/03-11/SAT-03-11-2018_0 is 2018-11-03 12:18:16.964447
        # We use the timezone Etc/GMT+3 to move it back to (Etc/GMT+0) UTC+0
        assert pd.Series([datetime.fromisoformat('2018-11-03T09:18:16.964447')]).\
                    dt.tz_localize(tz='Etc/GMT+3').\
                    dt.tz_convert(tz="Etc/GMT+0").\
                    dt.tz_localize(None)[0]\
            ==\
                    pd.Timestamp('2018-11-03 12:18:16.964447')
        df['timestamp_micro_start'] = pd.to_datetime(df['timestamp_micro_start']).\
                                    dt.tz_localize(tz='Etc/GMT+3').\
                                    dt.tz_convert(tz="Etc/GMT+0").\
                                    dt.tz_localize(None).\
                                    astype(int) // 1000

        # Obtain last packet time
        df['timestamp_micro_end'] = df['timestamp_micro_start'] + df['duration']
        del df['duration']

        # Append
        dataframes.append(df)

    return pd.concat(dataframes)

def get_dataframes_botiot() -> pd.DataFrame:
    dataframes = []
    # Retrieve files
    files = glob(str(BOT_IOT_CSVS_PATH / "*.csv"))
    files = [f for f in files if f != str(BOT_IOT_FEATURE_NAMES)]
    files = natsorted(files)

    # Retrieve header names
    names = None
    with open(BOT_IOT_FEATURE_NAMES) as f:
        names = f.read().strip().split(',')
    
    for idx,file in enumerate(files):
        # Read dataframe
        print(f"{idx+1}/{len(files)} - Loading {file}")
        df = pd.read_csv(file, low_memory=False, header=None, names=names)

        # Keep only relevant columns
        df = df[["saddr", "daddr", 'stime', 'ltime', 'category', 'subcategory']]

        # Rename columns
        df = df.rename(columns={\
            'saddr': 'source_ip',\
            'daddr': 'dest_ip',\
            'stime': 'timestamp_micro_start',\
            'ltime': 'timestamp_micro_end',\
            'category': 'label_1',\
            'subcategory': 'label_2',\
        })

        # Convert timestamp to unix time
        # Times are expressed as unix timestamps as seconds with a decimal part
        df['timestamp_micro_start'] = (df['timestamp_micro_start'] * 1_000_000)\
                                      .astype(int)
        df['timestamp_micro_end'] = (df['timestamp_micro_end'] * 1_000_000)\
                                      .astype(int)
        
        # Join label parts
        df["label"] = df["label_1"] + '_' + df["label_2"]
        del df["label_1"]
        del df["label_2"]

        # Append
        dataframes.append(df)

    return pd.concat(dataframes)

def get_dataframes_toniot() -> pd.DataFrame:
    dataframes = []

    # Retrieve files
    files = glob(str(TON_IOT_CSVS_PATH / "*.csv"))
    files = natsorted(files)
    
    for idx,file in enumerate(files):
        # Read dataframe
        print(f"{idx+1}/{len(files)} - Loading {file}")
        df = pd.read_csv(file, low_memory=False)

        # Keep only relevant columns
        df = df[["src_ip", "dst_ip", 'ts', 'duration', 'type']]

        # Rename columns
        df = df.rename(columns={\
            'src_ip': 'source_ip',\
            'dst_ip': 'dest_ip',\
            'ts': 'timestamp_micro_start',\
            'duration': 'duration',\
            'type': 'label'
        })

        # Convert timestamp to unix time
        # Times are expressed as unix timestamps as seconds
        df['timestamp_micro_start'] = (df['timestamp_micro_start'] * 1_000_000)\
                                      .astype(int)
        
        # Convert duration to microseconds
        df['duration'] = (df['duration'] * 1_000_000)\
                          .astype(int)
        
        # Force a minimum duration
        df['duration'] = np.maximum(df['duration'], 1)
        
        # Obtain last packet time
        df['timestamp_micro_end'] = df['timestamp_micro_start'] + df['duration']
        del df['duration']

        # Append
        dataframes.append(df)

    return pd.concat(dataframes)

def main():
    extract("TON-IoT", get_dataframes_toniot, TON_IOT_CSVS_PATH_RES)
    extract("BoT-IoT", get_dataframes_botiot, BOT_IOT_PATH_RES)
    extract("CIC-DDos2019", get_dataframes_cicddos_2019, CICDDOS_2019_CSVS_PATH_RES)

if __name__ == "__main__":
    main()
