import glob
from pathlib import Path

CSV_FOLDER_FIRST_DAY = Path("./tmp/cicddos2019-pcap-03-11")
CSV_FOLDER_SECOND_DAY = Path("./tmp/cicddos2019-pcap-03-11")

def get_conversations_csvs_in_folder(folder: str):
    return glob.glob(f"{folder}/*.csv")

print(get_conversations_csvs_in_folder(CSV_FOLDER_FIRST_DAY))
