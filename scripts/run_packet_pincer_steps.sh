#!/usr/bin/env bash

python3 -u /workspaces/tfg/scripts/extract_ground_truth_from_datasets.py
source /workspaces/tfg/scripts/execute_packet_pincer_on_data.sh
python3 -u /workspaces/tfg/scripts/packet_pincer_results_plots.py
python3 -u /workspaces/tfg/scripts/packet_pincer_results_plots_list.py
python3 -u /workspaces/tfg/scripts/packet_pincer_preprocess_results.py
python3 -u /workspaces/tfg/scripts/packet_pincer_train_models.py

