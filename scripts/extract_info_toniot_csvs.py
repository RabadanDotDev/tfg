import glob
import pandas as pd
import json
from pathlib import Path
from natsort import natsorted

RESULT_FILENAME = Path("./tmp/info_toniot.json")
CSV_FOLDER = Path("/Datasets/TON-IoT/Processed_datasets/Processed_Network_dataset/")

def dump_as_json(file: str, object):
    with open(file, 'w') as f:
        f.write(json.dumps(object))

def get_csv_list_in_folder(folder: str):
    return natsorted([f for f in glob.glob(f"{folder}/*.csv")])

def get_csvs_in_folder_as_pandas(folder: str):
    files = get_csv_list_in_folder(folder)
    df = pd.concat([pd.read_csv(file)[['ts', 'duration', 'type']] for file in files])

    return df

def analyze_df(df):
    results = {}

    # Evaluate types
    type_value_counts = df[['type']].value_counts()
    for idx,number in enumerate(type_value_counts):
        type = type_value_counts.index[idx][0]

        start_time = df.loc[df['type'] == type]['ts'].min()
        last_time  = (df.loc[df['type'] == type]['ts'] + df.loc[df['type'] == type]['duration']).max()

        results[type] = {
            "count": int(number), 
            "start_time": float(start_time),
            "last_time" : float(last_time)
        }

    return results

def main():
    df = get_csvs_in_folder_as_pandas(CSV_FOLDER)
    results = analyze_df(df)
    dump_as_json(RESULT_FILENAME, results)

if __name__ == "__main__":
    main()
