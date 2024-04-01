from matplotlib.dates import DateFormatter
import numpy as np  
import matplotlib.pyplot as plt
import distinctipy
import json
from pathlib import Path
from datetime import datetime, timedelta

RESULT_FOLDER = Path("./tmp/")
RESULT_FILENAME = "info_toniot.json"
REPORT_MEDIA_FOLDER = Path("./report/media/")

def read_from_json(file: str):
    with open(file, 'r') as f:
        return json.loads(f.read())

def get_text_color_from_bg(background_color):
    return (0,0,0) if (background_color[0]*0.299 + background_color[1]*0.587 + background_color[2]*0.114) > 150/255 else (1,1,1)

def generate_histogram_categories(results):
    bar_labels = []
    bar_y_positions = []

    index = 0

    for type in results:
        bar_labels.append(f"{type}")
        bar_y_positions.append(results[type]['count'])
        index = index + 1

    colors = distinctipy.get_colors(len(bar_labels), pastel_factor=0.7)

    for bar_label, bar_y_position, color in zip(bar_labels, bar_y_positions, colors):
        plt.bar(bar_label, bar_y_position, label=bar_label, color = color)

    plt.yscale('log')
    plt.ylabel("Número de flujos")
    plt.xticks(rotation=-90)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./toniot_csv_results.png', bbox_inches="tight")

def generate_timeline(results):
    # Generate a sorted list of categories
    types = []
    for type in results:
        if type == "normal":
            continue
        types.append({
            "start_time": datetime.fromtimestamp(results[type]['start_time']),
            "last_time": datetime.fromtimestamp(results[type]['last_time']),
            "type": type
        })
    types = sorted(types, key=lambda v: v["start_time"])

    plt.clf()
    fig, ax = plt.subplots(figsize=(20, 5), ncols=1)

    # Convert the list of the types to the broken_barh format
    types_bars = []
    types_names = []
    types_annotation_pos = []

    for type in types:        
        # Add category bars
        types_bars.append((type["start_time"], type["last_time"] - type["start_time"]))
        types_names.append(type['type'])
        types_annotation_pos.append((type["start_time"] + (type["last_time"] - type["start_time"])/2, 10+15/2))

    # Gen colors
    types_bars_col = distinctipy.get_colors(len(types_bars), pastel_factor=0.7)

    # Plot
    ax.broken_barh(types_bars, (10, 15), facecolors=types_bars_col)
    for category_name,category_annotation_pos,category_bar_color in zip(types_names, types_annotation_pos, types_bars_col):
        text_color = get_text_color_from_bg(category_bar_color)
        ax.annotate(category_name, category_annotation_pos, verticalalignment="center", horizontalalignment='center', rotation=90, color=text_color)

    # Set axis
    ax.set_yticks([])
    ax.xaxis.set_major_formatter(DateFormatter("%m-%d %H:%M"))
    plt.xticks(np.arange(types[0]["start_time"], types[-1]["last_time"]+timedelta(hours=4), timedelta(hours=4)))

    fig.autofmt_xdate()
    plt.subplots_adjust(wspace=0, hspace=0)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./toniot_csv_timeline.png', bbox_inches="tight")


def main():
    RESULT_FOLDER.mkdir(parents=True, exist_ok=True)
    results = read_from_json(RESULT_FOLDER / RESULT_FILENAME)
    generate_histogram_categories(results)
    generate_timeline(results)

if __name__ == "__main__":
    main()
