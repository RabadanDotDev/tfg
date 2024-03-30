import glob
import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

CSV_FOLDER = Path("./tmp/botiot")
TABLE_RESULT_TREE = Path("./report/theoretical_framework/datasets_botiot_protos.tex")
TABLE_RESULT_IP = Path("./report/theoretical_framework/datasets_botiot_protosip.tex")
RESULT_FOLDER = Path("./tmp/")
REPORT_MEDIA_FOLDER = Path("./report/media/")
TREEPROTO_HEADER=5
TREEPROTO_FOOTER=1
IPPROTO_HEADER=5
IPPROTO_FOOTER=2

units = {"bytes": 1, "kB": 2**10, "MB": 2**20, "GB": 2**30, "TB": 2**40}
def parse_size(size):
    number, unit = [string.strip() for string in size.split()]
    return int(float(number)*units[unit])

def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def dump_as_json(file: str, object):
    with open(file, 'w') as f:
        f.write(json.dumps(object))

def get_conversations_csvs_in_folder(folder: str):
    return glob.glob(f"{folder}/*.conv.csv")

def get_treeproto_txt_in_folder(folder: str):
    return glob.glob(f"{folder}/*.treeproto.txt")

def get_ipproto_txt_in_folder(folder: str):
    return glob.glob(f"{folder}/*.ipproto.txt")

def read_dataframes(files: list[str]) -> pd.DataFrame:
    return pd.concat([pd.read_csv(file, skipinitialspace=True) for file in files])

def get_conversations_from_folder(folder: str) -> pd.DataFrame:
    return read_dataframes(get_conversations_csvs_in_folder(folder))

def get_conversations() -> pd.DataFrame:
    return get_conversations_from_folder(CSV_FOLDER)

def get_unique_ips(conversations: pd.DataFrame) -> dict:
    res = {}

    res["num_total_day"] = pd.concat([
        conversations['ip origin'],
        conversations['ip dest'],
    ]).unique().size

    res["total_day"] = list(pd.concat([
        conversations['ip origin'],
        conversations['ip dest'],
    ]).unique())
   
    return res

def get_testbed_ips(conversations: pd.DataFrame) -> dict:
    res = {}

    res["internal_ips_total"] = list(pd.concat([
        conversations[conversations['ip origin'].str.contains("192.168.100.")]['ip origin'],
        conversations[conversations['ip dest'].str.contains("192.168.100.")]['ip dest'],
    ]).unique())

    return res

def plot_histograms(conversations: pd.DataFrame):
    plt.clf()
    fig, ax = plt.subplots()
    ax.set_yscale('log')
    plt.xlabel('Duración')
    plt.ylabel("Nº flujos")
    plt.hist(conversations['duration'], bins=30)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./botiot_pcap_duration_distribution.png', bbox_inches="tight")

    plt.clf()
    fig, ax = plt.subplots()
    ax.set_yscale('log')
    ax.set_xscale('log')
    plt.xlabel('Nº de bytes')
    plt.ylabel("Nº flujos")
    logbins = np.geomspace(conversations['bytes_total'].apply(parse_size).min(), conversations['bytes_total'].apply(parse_size).max(), 30)
    plt.hist(conversations['bytes_total'].apply(parse_size), bins=logbins)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./botiot_pcap_bytes_distribution.png', bbox_inches="tight")

    plt.clf()
    fig, ax = plt.subplots()
    ax.set_yscale('log')
    ax.set_xscale('log')
    plt.xlabel('Nº de tramas')
    plt.ylabel("Nº flujos")
    logbins = np.geomspace(conversations['frames_total'].min(), conversations['frames_total'].max(), 30)
    plt.hist(conversations['frames_total'], bins=logbins)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./botiot_pcap_frames_distribution.png', bbox_inches="tight")

def conversation_evaluate():
    conversations = get_conversations()
    unique_ips = get_unique_ips(conversations)
    testbed_ips = get_testbed_ips(conversations)

    dump_as_json(RESULT_FOLDER / 'botiot_unique_ips.json', unique_ips)
    dump_as_json(RESULT_FOLDER / 'botiot_testbed_ips.json', testbed_ips)
    
    plot_histograms(conversations)

def get_create_dict_list(dictionary: dict, list: list) -> dict:
    position = dictionary
    for idx,protocol in enumerate(list):
        if not 'subprotocols' in position:
            position['subprotocols'] = {}
        if not protocol in position['subprotocols']:
            position['subprotocols'][protocol] = {'frames_count':0, 'bytes_count':0, 'level' : idx}
        position = position['subprotocols'][protocol]
    return position

def treeproto_evaluate_file(file: str, contents: dict):
    lines = None
    with open(file) as f:
        lines = f.read().splitlines()[TREEPROTO_HEADER:-TREEPROTO_FOOTER]

    current_protocol_stack = []
    for line in lines:
        # Determine layer level
        leading_spaces = len(line) - len(line.lstrip(' '))
        level = leading_spaces//2 + 1

        # Remove format spaces
        line = ' '.join(line.split())

        # Extract protocol name and frames/bytes
        protocol, frames, bytes = line.split(' ')
        frames, bytes = int(frames.split(':')[1]), int(bytes.split(':')[1])

        # Update current protocol stack
        if level < len(current_protocol_stack):
            # Current level is lower than previous stack

            # Remove extra levels
            current_protocol_stack = current_protocol_stack[:level]

            # Set top level with current protocol
            if len(current_protocol_stack) != 0:
                current_protocol_stack.pop()
            current_protocol_stack.append(protocol)
        elif level == len(current_protocol_stack):
            # We are in the same level of the stack 

            # Set top level with current protocol
            if len(current_protocol_stack) != 0:
                current_protocol_stack.pop()
            current_protocol_stack.append(protocol)
        elif level == len(current_protocol_stack) + 1:
            # We added one layer

            # Add current protocol
            current_protocol_stack.append(protocol)
        else:
            print("error")

        # Update contents
        position = get_create_dict_list(contents, current_protocol_stack)
        position['frames_count'] += frames
        position['bytes_count'] += bytes

    return contents

def tree_proto_gen_tex_table_lines(contents, maxlevel, parents = [], level=0):
    lines = []

    for key in contents:
        subprotocols = len(contents[key]['subprotocols']) if 'subprotocols' in contents[key] else 0
        protocols = parents + [key]
        
        protocols_str = ""
        for i in range(maxlevel+1):
            protocols_str += f"{protocols[i]} &" if i < len(protocols) else "- &"

        lines.append(f"{protocols_str} {contents[key]['frames_count']:.2e} & {sizeof_fmt(contents[key]['bytes_count'])} & {subprotocols} \\\\")

        if maxlevel != level and subprotocols != 0:
            lines.extend(tree_proto_gen_tex_table_lines(contents[key]['subprotocols'], maxlevel, protocols, level+1))

    return lines

def tree_proto_gen_tex_table(contents):
    lines = []
    # Generate opening lines
    lines.append(r'%Generated with ' + __file__)
    lines.append(r'\begin{table}[H]')
    lines.append(r'    \begin{center}')
    lines.append(r'        \begin{tabular}{|c c c | c c c|} ')
    lines.append(r'            \hline')
    lines.append(r'            \textbf{L0} & \textbf{L1} & \textbf{L2} & \textbf{Tramas} & \textbf{Bytes} & \textbf{Nº subprotocolos}\\')
    lines.append(r'            \hline\hline')

    # Generate contents
    lines.extend(tree_proto_gen_tex_table_lines(contents, 2))
    
    # Generate closing lines
    lines.append(r'            \hline')
    lines.append(r'        \end{tabular}')
    lines.append(r'    \end{center}')
    lines.append(r'    \caption{Primeras tres capas de protocolos identificados en BoT-IoT}')
    lines.append(r'    \label{table:botiotprotocols}')
    lines.append(r'\end{table}')

    # Write file
    with open(TABLE_RESULT_TREE, 'w') as f:
        f.writelines(s + '\n' for s in lines)


def treeproto_evaluate_files():
    contents = {}

    for file in get_treeproto_txt_in_folder(CSV_FOLDER):
        contents = treeproto_evaluate_file(file, contents)

    contents = contents['subprotocols']

    dump_as_json(RESULT_FOLDER / 'botiot_tree_proto_combined.json', contents)
    tree_proto_gen_tex_table(contents)

def ipproto_evaluate_file(file, contents):
    lines = None
    with open(file) as f:
        lines = f.read().splitlines()[IPPROTO_HEADER:-IPPROTO_FOOTER]
    for line in lines:
        # Remove leading space
        line = line.lstrip()

        # Remove padding space
        line = ' '.join(line.split())

        # Separate by spaces
        line = line.split()

        # Remove "Protocol" and "Types" in the case of ['IP', 'Protocol', 'Types', ...]
        if 'Protocol' in line:
            line.remove('Protocol')
        if 'Types' in line:
            line.remove('Types')

        # Extract protocol + count
        protocol = line[0]
        count = line[1]

        # Include in contents
        if not protocol in contents:
            contents[protocol] = {'count': int(count)}
        else:
            contents[protocol]['count'] += int(count)

    return contents

def ipproto_compute_percentages(contents):
    total = contents['IP']['count']

    for key in contents:
        contents[key]['percentage'] = contents[key]['count']/total*100

    return contents

def ip_proto_gen_tex_table(contents):
    lines = []
    # Generate opening lines
    lines.append(r'%Generated with ' + __file__)
    lines.append(r'\begin{table}[H]')
    lines.append(r'    \begin{center}')
    lines.append(r'        \begin{tabular}{|c | c c|} ')
    lines.append(r'            \hline')
    lines.append(r'            \textbf{Protocolo} & \textbf{Nº Tramas} & \textbf{Porcentaje}\\')
    lines.append(r'            \hline\hline')

    # Generate contents
    for key in contents:
        lines.append(f"{key} & {contents[key]['count']:.2e} & {contents[key]['percentage']:.3f} \\\\")
    
    # Generate closing lines
    lines.append(r'            \hline')
    lines.append(r'        \end{tabular}')
    lines.append(r'    \end{center}')
    lines.append(r'    \caption{Protocolos identificados analizando exclusivamente la capa IP en BoT-IoT}')
    lines.append(r'    \label{table:botiotprotocolsip}')
    lines.append(r'\end{table}')

    # Write file
    with open(TABLE_RESULT_IP, 'w') as f:
        f.writelines(s + '\n' for s in lines)

def ipproto_evaluate_files():
    contents = {}

    for file in get_ipproto_txt_in_folder(CSV_FOLDER):
        contents = ipproto_evaluate_file(file, contents)

    contents = ipproto_compute_percentages(contents)

    dump_as_json(RESULT_FOLDER / 'botiot_ip_proto_combined.json', contents)
    ip_proto_gen_tex_table(contents)

def main():
    conversation_evaluate()
    treeproto_evaluate_files()
    ipproto_evaluate_files()

if __name__ == "__main__":
    main()
