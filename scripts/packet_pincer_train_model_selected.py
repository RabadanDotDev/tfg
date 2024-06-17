#!/usr/bin/env python3

from datetime import datetime, time
import json
from pathlib import Path
from typing import Tuple
from matplotlib import pyplot as plt
from matplotlib.colors import LogNorm
import numpy as np
import pandas as pd
from sklearn import metrics
from sklearn.ensemble import AdaBoostClassifier, BaggingClassifier, ExtraTreesClassifier, RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.multiclass import unique_labels
import joblib
import seaborn as sns

TRAIN_CSV = Path("/workspaces/tfg/tmp/train.csv")
TEST_CSV = Path("/workspaces/tfg/tmp/test.csv")
VALIDATION_CSV = Path("/workspaces/tfg/tmp/validation.csv")
SCALER = Path("/workspaces/tfg/tmp/scaler.joblib")
KFOLD = Path("/workspaces/tfg/tmp/kfold.joblib")
REPORT_MEDIA_FOLDER = Path("/workspaces/tfg/report/media/")
PACKET_PINCER_LABEL = "label"
TMP_FOLDER = Path("/workspaces/tfg/tmp")

def train_run(df_train: pd.DataFrame, df_test: pd.DataFrame, name: str, model):
    print(f"{name} - Full train run")

    x_train = df_train.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_train = df_train.loc[: , df_train.columns == PACKET_PINCER_LABEL]

    x_test = df_test.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_test = df_test.loc[: , df_train.columns == PACKET_PINCER_LABEL]

    print(f"{name} - Training full model. Start time at {datetime.now()}")
    start_time = datetime.now()
    model.fit(x_train, y_train.values.ravel())
    elapsed_time = datetime.now() - start_time
    print(f"{name} - Training complete. Took {elapsed_time}")

    print(f"{name} - Predicting categories. Start time at {datetime.now()}")
    start_time = datetime.now()
    y_test_predictions = model.predict(x_test)
    elapsed_time = datetime.now() - start_time
    print(f"{name} - Predicting complete. Took {elapsed_time}")

    print(f"{name} - Generating classification report")
    clasification_report = metrics.classification_report(y_test, y_test_predictions, digits=6)
    clasification_report_dict = metrics.classification_report(y_test, y_test_predictions, output_dict=True)
    with open(TMP_FOLDER / "{name}_selected_classification_report.json", "w") as write_file:
        json.dump(clasification_report_dict, write_file)

    print(f"{name} - Plotting results")
    plt.clf()
    plt.figure(figsize=(8, 8))
    classes = unique_labels(y_test, y_test_predictions)
    cm = metrics.confusion_matrix(y_test, y_test_predictions)
    sns.heatmap(cm, annot=True, cmap='Blues', fmt='_d', cbar=False, xticklabels=classes, yticklabels=classes, norm=LogNorm())
    plt.xlabel('Predicted Labels')
    plt.ylabel('True Labels')
    plt.title('Confusion Matrix')
    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_model_{name}_selected.png", bbox_inches="tight")
    print(clasification_report)

def main() -> None:
    df_train_validation = pd.concat([pd.read_csv(TRAIN_CSV), pd.read_csv(VALIDATION_CSV)])
    df_test = pd.read_csv(TEST_CSV)
    train_run(df_train_validation, df_test, "random_forest", RandomForestClassifier(n_estimators=20))

if __name__=="__main__":
    main()
