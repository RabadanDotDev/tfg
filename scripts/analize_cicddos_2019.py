import glob
import pandas

def get_csvs_in_folder(folder: str):
    return glob.glob(f"{folder}/*.csv")

def analize_csv(file: str):
    df = pandas.read_csv(file, sep=',')

    # Show general information
    print(f"{file} has {df.shape[0]} rows and {df.shape[1]} columns")
    print(f">The column names are: {list(df.columns)}")
    for idx, na_num in enumerate(df.isna().sum()):
        if na_num != 0:
            print(f">>{df.columns[idx]} has {na_num} missing values")

    # Show ip information
    print(f">{df[[' Source IP']].drop_duplicates().shape[0]} unique origin ip addresses")
    print(f">{df[[' Destination IP']].drop_duplicates().shape[0]} unique destination ip addresses")
    print(f">{df[[' Source IP', ' Destination IP']].drop_duplicates().shape[0]} unique origin and destiny ip addresses pairs")

    # Show labeling information
    print(f">The dataset contains {df[[' Label']].drop_duplicates().shape[0]} labels")
    vc = df[' Label'].value_counts()
    for idx,number in enumerate(vc):
        first_time = df.loc[df[' Label'] == vc.index[idx]][' Timestamp'].min()
        last_time = df.loc[df[' Label'] == vc.index[idx]][' Timestamp'].max()
        
        print(f">>{vc.index[idx]} appears in {number} flows between {first_time} and {last_time}")

def main():
    for file in get_csvs_in_folder("/Datasets/CICDDoS2019/csv/03-11/"):
        analize_csv(file)
    for file in get_csvs_in_folder("/Datasets/CICDDoS2019/csv/01-12/"):
        analize_csv(file)

if __name__ == "__main__":
    main()