import glob
from datetime import datetime
import pandas

def get_csvs_in_folder(folder: str):
    return glob.glob(f"{folder}/*.csv")

def analize_csv(file: str):
    df = pandas.read_csv(file, sep=',')
    results = {}

    # Show general information
    print(f"{file} has {df.shape[0]} rows and {df.shape[1]} columns")
    print(f">The column names are: {list(df.columns)}")
    for idx, na_num in enumerate(df.isna().sum()):
        if na_num != 0:
            print(f">>{df.columns[idx]} has {na_num} missing values")
    results['first_csv_time'] = datetime.fromisoformat(df[' Timestamp'].min())
    results['last_csv_time'] = datetime.fromisoformat(df[' Timestamp'].max())
    print(f"Contains information from {results['first_csv_time']} to {results['last_csv_time']}")

    # Show ip information
    print(f">{df[[' Source IP']].drop_duplicates().shape[0]} unique origin ip addresses")
    print(f">{df[[' Destination IP']].drop_duplicates().shape[0]} unique destination ip addresses")
    print(f">{df[[' Source IP', ' Destination IP']].drop_duplicates().shape[0]} unique origin and destiny ip addresses pairs")

    # Show labeling information
    print(f">The dataset contains {df[[' Label']].drop_duplicates().shape[0]} labels")
    vc = df[' Label'].value_counts()
    results['labels'] = {}
    for idx,number in enumerate(vc):
        label = vc.index[idx]
        results['labels'][label] = {"number": number}
        results['labels'][label]['first_time'] = datetime.fromisoformat(df.loc[df[' Label'] == vc.index[idx]][' Timestamp'].min())
        results['labels'][label]['last_time'] = datetime.fromisoformat(df.loc[df[' Label'] == vc.index[idx]][' Timestamp'].max())
        print(f">>{label} appears in {number} flows between {results['labels'][label]['first_time']} and {results['labels'][label]['last_time']}")

    print(f"{results}")
    return results
    

def main():
    results = {"03-11": {}, "01-12" : {}}

    # Analize first file
    for file in get_csvs_in_folder("/Datasets/CICDDoS2019/csv/03-11/"):
        results["03-11"][file.split('/')[-1]] = analize_csv(file)

    for file in get_csvs_in_folder("/Datasets/CICDDoS2019/csv/01-12/"):
        results["01-12"][file.split('/')[-1]] = analize_csv(file)
    print(f"{results}")

if __name__ == "__main__":
    main()