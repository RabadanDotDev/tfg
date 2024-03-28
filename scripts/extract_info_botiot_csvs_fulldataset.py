import glob
import pandas as pd
import json
from pathlib import Path
from natsort import natsorted

RESULT_FILENAME = Path("./tmp/info_botiot.json")
CSV_FOLDER = Path("/Datasets/Bot-IoT/Dataset/Entire Dataset/")
CSV_FEATURE_NAMES = Path("/Datasets/Bot-IoT/Dataset/Entire Dataset/UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv")

def dump_as_json(file: str, object):
    with open(file, 'w') as f:
        f.write(json.dumps(object))

def get_csv_header():
    with open(CSV_FEATURE_NAMES) as f:
        return f.read().strip().split(',')

def get_csv_list_in_folder(folder: str):
    return natsorted([f for f in glob.glob(f"{folder}/*.csv") if f != str(CSV_FEATURE_NAMES)])

def get_csvs_in_folder_as_pandas(folder: str):
    files = get_csv_list_in_folder(folder)
    names = get_csv_header()
    df = pd.concat([pd.read_csv(file, header=None, names=names)[['stime', 'ltime', 'category', 'subcategory']] for file in files])

    return df

def analyze_df(df):
    results = {}

    # Evaluate categories
    category_value_counts = df[['category']].value_counts()
    for idx,number in enumerate(category_value_counts):
        category = category_value_counts.index[idx][0]

        start_time = df.loc[df['category'] == category]['stime'].min()
        last_time  = df.loc[df['category'] == category]['ltime'].max()

        results[category] = {
            "count": number, 
            "start_time": start_time,
            "last_time" : last_time,
            "subcategories": {}
        }

    # Evaluate subcategories
    subcategory_value_counts = df[['category', 'subcategory']].value_counts()
    for idx,number in enumerate(subcategory_value_counts):
        category = subcategory_value_counts.index[idx][0]
        subcategory = subcategory_value_counts.index[idx][1]

        start_time = df.loc[(df['category'] == category) & (df['subcategory'] == subcategory)]['stime'].min()
        last_time  = df.loc[(df['category'] == category) & (df['subcategory'] == subcategory)]['ltime'].max()

        results[category]['subcategories'][subcategory] = {
            "count": number, 
            "start_time": start_time,
            "last_time" : last_time
        }

    return results

def main():
    df = get_csvs_in_folder_as_pandas(CSV_FOLDER)
    results = analyze_df(df)
    dump_as_json(RESULT_FILENAME, results)

if __name__ == "__main__":
    main()
