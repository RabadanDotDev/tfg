
import numpy as np  
import matplotlib.pyplot as plt
import distinctipy
import json
from pathlib import Path

RESULT_FOLDER = Path("./tmp/")
RESULT_FILENAME = "info_cicddos_2019.json"
REPORT_MEDIA_FOLDER = Path("./report/media/")

def read_from_json(file: str):
    with open(file, 'r') as f:
        return json.loads(f.read())

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
                # Ignore prefix if it exists
                label_clean = label.split("_")[-1]

                # Count
                if label_clean in label_counts:
                    label_counts[label_clean] += results[day][file]['labels'][label]['number']
                else:
                    label_counts[label_clean] = results[day][file]['labels'][label]['number']

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

def main():
    RESULT_FOLDER.mkdir(parents=True, exist_ok=True)
    results = read_from_json(RESULT_FOLDER / RESULT_FILENAME)
    generate_bars_labels_by_file(results)
    generate_histogram_labels_full(results)

if __name__ == "__main__":
    main()
