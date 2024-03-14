import glob
import pandas

def get_csvs_in_folder(folder: str):
    return glob.glob(f"{folder}/*.csv")

def analize_csv(file: str):
    df = pandas.read_csv(file, sep=',')
    print(f"{file} has {df.shape[0]} rows and {df.shape[1]} columns")
    print(f"The column names are: {list(df.columns)}")

    for idx, na_num in enumerate(df.isna().sum()):
        print(f"{df.index[idx]} has {na_num} missing values")

def main():
    for file in get_csvs_in_folder("/Datasets/CICDDoS2019/csv/03-11/"):
        analize_csv(file)
    for file in get_csvs_in_folder("/Datasets/CICDDoS2019/csv/01-12/"):
        analize_csv(file)

if __name__ == "__main__":
    main()