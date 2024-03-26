import glob
import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

CSV_FOLDER_FIRST_DAY = Path("./tmp/cicddos2019-pcap-03-11")
CSV_FOLDER_SECOND_DAY = Path("./tmp/cicddos2019-pcap-01-12")
RESULT_FOLDER = Path("./tmp/")
REPORT_MEDIA_FOLDER = Path("./report/media/")

units = {"bytes": 1, "kB": 2**10, "MB": 2**20, "GB": 2**30, "TB": 2**40}
def parse_size(size):
    number, unit = [string.strip() for string in size.split()]
    return int(float(number)*units[unit])

def dump_as_json(file: str, object):
    with open(file, 'w') as f:
        f.write(json.dumps(object))

def get_conversations_csvs_in_folder(folder: str):
    return glob.glob(f"{folder}/*.conv.csv")

def read_dataframes(files: list[str]) -> pd.DataFrame:
    return pd.concat([pd.read_csv(file, skipinitialspace=True) for file in files])

def get_conversations_from_folder(folder: str) -> pd.DataFrame:
    return read_dataframes(get_conversations_csvs_in_folder(folder))

def get_conversations() -> pd.DataFrame:
    conversations_first_day = get_conversations_from_folder(CSV_FOLDER_FIRST_DAY)
    conversations_second_day = get_conversations_from_folder(CSV_FOLDER_SECOND_DAY)

    conversations_first_day['day'] = 'first'
    conversations_second_day['day'] = 'second'

    return pd.concat([conversations_first_day, conversations_second_day])

def get_unique_ips(conversations: pd.DataFrame) -> dict:
    res = {}

    res["num_first_day"] = pd.concat([
        conversations[conversations['day'] == 'first']['ip origin'],
        conversations[conversations['day'] == 'first']['ip dest']
    ]).unique().size

    res["num_second_day"] = pd.concat([
        conversations[conversations['day'] == 'second']['ip origin'],
        conversations[conversations['day'] == 'second']['ip dest'],
    ]).unique().size

    res["num_total_day"] = pd.concat([
        conversations['ip origin'],
        conversations['ip dest'],
    ]).unique().size

    res["first_day"] = list(pd.concat([
        conversations[conversations['day'] == 'first']['ip origin'],
        conversations[conversations['day'] == 'first']['ip dest']
    ]).unique())

    res["second_day"] = list(pd.concat([
        conversations[conversations['day'] == 'second']['ip origin'],
        conversations[conversations['day'] == 'second']['ip dest'],
    ]).unique())

    res["total_day"] = list(pd.concat([
        conversations['ip origin'],
        conversations['ip dest'],
    ]).unique())
   
    return res

def get_testbed_ips(conversations: pd.DataFrame) -> dict:
    res = {}

    res["internal_ips_first_day"] = list(pd.concat([
        conversations[(conversations['day'] == 'first') & (conversations['ip origin'].str.contains("192.168.50."))]['ip origin'],
        conversations[(conversations['day'] == 'first') & (conversations['ip dest'].str.contains("192.168.50."))]['ip dest'],
    ]).unique())

    res["internal_ips_second_day"] = list(pd.concat([
        conversations[(conversations['day'] == 'second') & conversations['ip origin'].str.contains("192.168.50.")]['ip origin'],
        conversations[(conversations['day'] == 'second') & conversations['ip dest'].str.contains("192.168.50.")]['ip dest'],
    ]).unique())

    res["internal_ips_total"] = list(pd.concat([
        conversations[conversations['ip origin'].str.contains("192.168.50.")]['ip origin'],
        conversations[conversations['ip dest'].str.contains("192.168.50.")]['ip dest'],
    ]).unique())

    return res

def plot_histograms(conversations: pd.DataFrame):
    plt.clf()
    fig, ax = plt.subplots()
    ax.set_yscale('log')
    plt.xlabel('Duración')
    plt.ylabel("Nº flujos")
    plt.hist([conversations[conversations['day'] == 'first']['duration'], conversations[conversations['day'] == 'second']['duration']], bins=30, label=["Primer dia (3 de Noviembre)", "Segundo dia (1 de Diciembre)"])
    plt.legend()
    plt.savefig(REPORT_MEDIA_FOLDER / f'./cicddos_2019_pcap_duration_distribution.png', bbox_inches="tight")

    plt.clf()
    fig, ax = plt.subplots()
    ax.set_yscale('log')
    ax.set_xscale('log')
    plt.xlabel('Nº de bytes')
    plt.ylabel("Nº flujos")
    logbins = np.geomspace(conversations['bytes_total'].apply(parse_size).min(), conversations['bytes_total'].apply(parse_size).max(), 30)
    plt.hist([conversations[conversations['day'] == 'first']['bytes_total'].apply(parse_size), conversations[conversations['day'] == 'second']['bytes_total'].apply(parse_size)], bins=logbins, label=["Primer dia (3 de Noviembre)", "Segundo dia (1 de Diciembre)"])
    plt.legend()
    plt.savefig(REPORT_MEDIA_FOLDER / f'./cicddos_2019_pcap_bytes_distribution.png', bbox_inches="tight")

    plt.clf()
    fig, ax = plt.subplots()
    ax.set_yscale('log')
    ax.set_xscale('log')
    plt.xlabel('Nº de tramas')
    plt.ylabel("Nº flujos")
    logbins = np.geomspace(conversations['frames_total'].min(), conversations['frames_total'].max(), 30)
    plt.hist([conversations[conversations['day'] == 'first']['frames_total'], conversations[conversations['day'] == 'second']['frames_total']], bins=logbins, label=["Primer dia (3 de Noviembre)", "Segundo dia (1 de Diciembre)"])
    plt.legend()
    plt.savefig(REPORT_MEDIA_FOLDER / f'./cicddos_2019_pcap_frames_distribution.png', bbox_inches="tight")


def main():
    conversations = get_conversations()
    unique_ips = get_unique_ips(conversations)
    testbed_ips = get_testbed_ips(conversations)

    dump_as_json(RESULT_FOLDER / 'cicddos2019_unique_ips.json', unique_ips)
    dump_as_json(RESULT_FOLDER / 'cicddos2019_testbed_ips.json', testbed_ips)
    
    plot_histograms(conversations)

if __name__ == "__main__":
    main()