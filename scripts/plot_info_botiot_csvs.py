from matplotlib.dates import DateFormatter
import numpy as np  
import matplotlib.pyplot as plt
import distinctipy
import json
from pathlib import Path
from datetime import datetime

RESULT_FOLDER = Path("./tmp/")
RESULT_FILENAME = "info_botiot.json"
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

    for category in results:
        for subcategory in results[category]['subcategories']:
            bar_labels.append(f"{category}-{subcategory}")
            bar_y_positions.append(results[category]['subcategories'][subcategory]['count'])

            index = index + 1

    colors = distinctipy.get_colors(len(bar_labels), pastel_factor=0.7)

    for bar_label, bar_y_position, color in zip(bar_labels, bar_y_positions, colors):
        plt.bar(bar_label, bar_y_position, label=bar_label, color = color)

    plt.yscale('log')
    plt.ylabel("Número de flujos")
    plt.xticks(rotation=-90)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./botiot_csv_day_results.png', bbox_inches="tight")

def generate_timeline(results):
    # Generate a sorted list of categories
    categories = []
    for category in results:
        if category == "Normal":
            continue
        categories.append({
            "start_time": datetime.fromtimestamp(results[category]['start_time']),
            "last_time": datetime.fromtimestamp(results[category]['last_time']),
            "category": category
        })
    categories = sorted(categories, key=lambda v: v["start_time"])
    
    # Generate a sorted list of subcategories
    subcategories = []
    for category in results:
        if category == "Normal":
            continue
        for subcategory in results[category]['subcategories']:
            subcategories.append({
                "start_time": datetime.fromtimestamp(results[category]['subcategories'][subcategory]['start_time']),
                "last_time": datetime.fromtimestamp(results[category]['subcategories'][subcategory]['last_time']),
                "category": category,
                "subcategory": subcategory
            })
    subcategories = sorted(subcategories, key=lambda v: v["start_time"])

    plt.clf()
    fig, ax = plt.subplots(figsize=(20, 5), ncols=3)

    for idx,category_group in enumerate([['Reconnaissance'], ['DoS', 'DDoS'], ['Theft']]):
        # Convert the list of the categories to the broken_barh format
        categories_bars = []
        categories_names = []
        categories_annotation_pos = []

        for category in categories:
            if not category['category'] in category_group:
                continue;
            
            # Add category bars
            categories_bars.append((category["start_time"], category["last_time"] - category["start_time"]))
            categories_names.append(category['category'])
            categories_annotation_pos.append((category["start_time"] + (category["last_time"] - category["start_time"])/2, 10+15/2))

        # Convert the list of the subcategories to the broken_barh format
        subcategories_bars = []
        subcategories_names = []
        subcategories_annotation_pos = []

        for subcategory in subcategories:
            if not subcategory['category'] in category_group:
                continue;
            
            subcategories_bars.append((subcategory["start_time"], subcategory["last_time"] - subcategory["start_time"]))
            subcategories_names.append(subcategory['subcategory'])
            subcategories_annotation_pos.append((subcategory["start_time"] + (subcategory["last_time"] - subcategory["start_time"])/2, 10+15+1+15/2))

        # Gen colors
        categories_bars_col = distinctipy.get_colors(len(categories_bars), pastel_factor=0.7)
        subcategories_bars_col = distinctipy.get_colors(len(subcategories_bars), pastel_factor=0.7)

        # Plot
        ax[idx].broken_barh(categories_bars, (10, 15), facecolors=categories_bars_col)
        for category_name,category_annotation_pos,category_bar_color in zip(categories_names, categories_annotation_pos, categories_bars_col):
            text_color = get_text_color_from_bg(category_bar_color)
            ax[idx].annotate(category_name, category_annotation_pos, verticalalignment="center", horizontalalignment='center', rotation=90, color=text_color)

        ax[idx].broken_barh(subcategories_bars, (10+15+1, 15), facecolors=subcategories_bars_col)
        for subcategory_name,subcategory_annotation_pos,subcategory_bar_color in zip(subcategories_names, subcategories_annotation_pos, subcategories_bars_col):
            text_color = get_text_color_from_bg(subcategory_bar_color)
            ax[idx].annotate(subcategory_name, subcategory_annotation_pos, verticalalignment="center", horizontalalignment='center', rotation=90, color=text_color, fontsize=7)

        # Set axis
        ax[idx].set_yticks([])
        ax[idx].xaxis.set_major_formatter(DateFormatter("%m-%d %H:%M"))
    fig.autofmt_xdate()
    plt.subplots_adjust(wspace=0, hspace=0)
    plt.savefig(REPORT_MEDIA_FOLDER / f'./botiot_csv_timeline.png', bbox_inches="tight")


def main():
    RESULT_FOLDER.mkdir(parents=True, exist_ok=True)
    results = read_from_json(RESULT_FOLDER / RESULT_FILENAME)
    generate_histogram_categories(results)
    generate_timeline(results)

if __name__ == "__main__":
    main()
