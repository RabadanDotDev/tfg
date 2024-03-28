
from matplotlib.dates import DateFormatter
import numpy as np  
import matplotlib.pyplot as plt
import distinctipy
import json
from pathlib import Path
from datetime import datetime

RESULT_FOLDER = Path("./tmp/")
RESULT_FILENAME = "info_cicddos_2019.json"
REPORT_MEDIA_FOLDER = Path("./report/media/")

def read_from_json(file: str):
    with open(file, 'r') as f:
        return json.loads(f.read())

def get_text_color_from_bg(background_color):
    return (0,0,0) if (background_color[0]*0.299 + background_color[1]*0.587 + background_color[2]*0.114) > 150/255 else (1,1,1)

def generate_bars_labels_by_file(results: dict):
    for day in results:
        plt.clf()
        group_width = 0.8
        plot_data = {"BENIGN" : {
            'bar_x_position' : [],
            'bar_y_length' : [],
            'bar_x_length' : [],
        }}

        # Generate bars
        for x_axis,file in enumerate(results[day]):
            x_axis_bar_group_start = x_axis - group_width/2
            x_axis_label_width = group_width/len(results[day][file]['labels'])
            for bar_num,label in enumerate(sorted(results[day][file]['labels'].keys())):
                bar_x_position = x_axis_bar_group_start + x_axis_label_width*bar_num + x_axis_label_width/2
                bar_y_length = results[day][file]['labels'][label]['number']
                bar_x_length = x_axis_label_width

                if label in plot_data:
                    plot_data[label]['bar_x_position'].append(bar_x_position)
                    plot_data[label]['bar_y_length'].append(bar_y_length)
                    plot_data[label]['bar_x_length'].append(bar_x_length)
                else:
                    plot_data[label] = {
                        'bar_x_position' : [bar_x_position],
                        'bar_y_length' : [bar_y_length],
                        'bar_x_length' : [bar_x_length],
                    }

        colors = distinctipy.get_colors(len(plot_data), pastel_factor=0.7)

        # Plot bars
        for label,color in zip(plot_data, colors):
            plt.bar(plot_data[label]['bar_x_position'], plot_data[label]['bar_y_length'], plot_data[label]['bar_x_length'], label=label, color = color)

        # Set axis
        plt.xticks(np.arange(len(results[day])), results[day].keys(), rotation='vertical')
        plt.xlabel("Archivo")
        plt.ylabel("Número de flujos")
        plt.yscale('log')
        plt.legend(bbox_to_anchor=(1, 1))

        plt.savefig(REPORT_MEDIA_FOLDER / f'./cicddos_2019_csv_{day}_file_results.png', bbox_inches="tight")

def generate_histogram_labels_full(results):
    plt.clf()
    fig, ax = plt.subplots(figsize=(12, 6))
    group_width = 0.8
    plot_data = {"BENIGN" : {
        'bar_x_position' : [],
        'bar_y_length' : [],
        'bar_x_length' : [],
    }}

    for x_axis,day in enumerate(results):
        # Count number of labels of the day
        label_counts = {}
        for file in results[day]:
            for label in (results[day][file]['labels'].keys()):
                # Count
                if label in label_counts:
                    label_counts[label] += results[day][file]['labels'][label]['number']
                else:
                    label_counts[label] = results[day][file]['labels'][label]['number']

        # Generate bars
        x_axis_bar_group_start = x_axis - group_width/2
        x_axis_label_width = group_width/len(label_counts)
        
        for bar_num,label in enumerate(sorted(label_counts.keys())):
            bar_x_position = x_axis_bar_group_start + x_axis_label_width*bar_num + x_axis_label_width/2
            bar_y_length = label_counts[label]
            bar_x_length = x_axis_label_width

            if label in plot_data:
                plot_data[label]['bar_x_position'].append(bar_x_position)
                plot_data[label]['bar_y_length'].append(bar_y_length)
                plot_data[label]['bar_x_length'].append(bar_x_length)
            else:
                plot_data[label] = {
                    'bar_x_position' : [bar_x_position],
                    'bar_y_length' : [bar_y_length],
                    'bar_x_length' : [bar_x_length],
                }

    # Plot bars
    colors = distinctipy.get_colors(len(plot_data), pastel_factor=0.7)
    for label,color in zip(plot_data, colors):
        plt.bar(plot_data[label]['bar_x_position'], plot_data[label]['bar_y_length'], plot_data[label]['bar_x_length'], label=label, color = color)

    # Set axis
    plt.xticks(np.arange(len(results)), results.keys(), rotation='vertical')
    plt.xlabel("Día")
    plt.ylabel("Número de flujos")
    plt.yscale('log')
    plt.legend(bbox_to_anchor=(1, 1))

    plt.savefig(REPORT_MEDIA_FOLDER / f'./cicddos_2019_csv_day_results.png', bbox_inches="tight")

def generate_timeline(results):
    for day in results:
        plt.clf()
        fig, ax = plt.subplots(figsize=(20, 5))

        # Generate a sorted list of csv times
        file_times = []
        for file in results[day]:
            file_times.append({
                "first_csv_time": datetime.fromisoformat(results[day][file]['first_csv_time']),
                "last_csv_time": datetime.fromisoformat(results[day][file]['last_csv_time']),
                "file": file
            })
        file_times = sorted(file_times, key=lambda v: v["first_csv_time"])
        
        # Convert the list of the csv to the broken_barh format
        file_times_increments = []
        for file in file_times:
            file_times_increments.append((file["first_csv_time"], file["last_csv_time"] - file["first_csv_time"]))

        # Plot the list of values
        file_times_increments_col = distinctipy.get_colors(len(file_times_increments), pastel_factor=0.7)
        plt.broken_barh(file_times_increments, (10, 15), facecolors=file_times_increments_col)

        # Annotate each file
        for file,background_color in zip(file_times, file_times_increments_col):
            text_color = get_text_color_from_bg(background_color)
            plt.annotate(file["file"], (file["first_csv_time"] + (file["last_csv_time"] - file["first_csv_time"])/2, 10+15/2), verticalalignment="center", horizontalalignment='center', rotation=90, color=text_color)

        # Generate a sorted list of attack times
        attack_times = []
        for file in results[day]:
            for label in results[day][file]['labels']:
                if label == 'BENIGN':
                    continue
                attack_times.append({
                    "first_time": datetime.fromisoformat(results[day][file]['labels'][label]['first_time']),
                    "last_time": datetime.fromisoformat(results[day][file]['labels'][label]['last_time']),
                    "attack": label
                })
        attack_times = sorted(attack_times, key=lambda v: v["first_time"])

        # Convert the list of the attacks to the broken_barh format
        attack_times_increments = []
        for attack in attack_times:
            attack_times_increments.append((attack["first_time"], attack["last_time"] - attack["first_time"]))

        # Plot the list of values
        attack_times_increments_col = distinctipy.get_colors(len(attack_times_increments), pastel_factor=0.7)
        plt.broken_barh(attack_times_increments, (10+15+1, 15), facecolors=attack_times_increments_col)

        # Annotate each attack
        for attack,background_color in zip(attack_times, attack_times_increments_col):
            text_color = get_text_color_from_bg(background_color)
            plt.annotate(attack["attack"], (attack["first_time"] + (attack["last_time"] - attack["first_time"])/2, 10+15+1+15/2), verticalalignment="center", horizontalalignment='center', rotation=90, color=text_color)

        # Set axis
        plt.yticks([])
        ax.xaxis.set_major_formatter(DateFormatter("%m-%d %H:%M"))
        plt.savefig(REPORT_MEDIA_FOLDER / f'./cicddos_2019_csv_{day}_timeline.png', bbox_inches="tight")

def main():
    RESULT_FOLDER.mkdir(parents=True, exist_ok=True)
    results = read_from_json(RESULT_FOLDER / RESULT_FILENAME)
    generate_bars_labels_by_file(results)
    generate_histogram_labels_full(results)
    generate_timeline(results)

if __name__ == "__main__":
    main()
