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
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.multiclass import unique_labels
import joblib
import seaborn as sns

TRAIN_CSV = Path("/workspaces/tfg/tmp/train.csv")
TEST_CSV = Path("/workspaces/tfg/tmp/test.csv")
SCALER = Path("/workspaces/tfg/tmp/scaler.joblib")
KFOLD = Path("/workspaces/tfg/tmp/kfold.joblib")
REPORT_MEDIA_FOLDER = Path("/workspaces/tfg/report/media/")
PACKET_PINCER_LABEL = "label"
TMP_FOLDER = Path("/workspaces/tfg/tmp")

SAMPLING_PERCENTAGE=0.15/100
TEST_PERCENTAGE=20/100
K_FOLD_SPLITS=5

def read_files() -> Tuple[pd.DataFrame, pd.DataFrame, MinMaxScaler, StratifiedKFold]:
    df_train = pd.read_csv(TRAIN_CSV)
    df_test = pd.read_csv(TEST_CSV)
    scaler = joblib.load(SCALER)
    skf = joblib.load(KFOLD)

    return (df_train, df_test, scaler, skf)

def cross_validation_run(df_train: pd.DataFrame, df_test: pd.DataFrame, skf: StratifiedKFold, name: str, model):
    print(f"{name} - Cross validation run")

    classification_reports = []
    
    x_train = df_train.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_train = df_train.loc[: , df_train.columns == PACKET_PINCER_LABEL]
    
    for i, (train_index, test_index) in enumerate(skf.split(x_train, y_train)):
        print(f"{name} - Working in fold {i}")
        
        # Split
        x_fold_train, X_fold_test = x_train.iloc[train_index], x_train.iloc[test_index]
        y_fold_train, y_fold_test = y_train.iloc[train_index], y_train.iloc[test_index]

        # Fit model
        model.fit(x_fold_train, y_fold_train.values.ravel())

        # Get predictions
        y_fold_predicted = model.predict(X_fold_test)

        # Evaluate results
        clasification_report = metrics.classification_report(y_fold_test, y_fold_predicted, output_dict=True)
        classification_reports.append(clasification_report)

    # Reformat classification reports
    print(f"{name} - Reformating kfold classification reports")
    accuracy_list = []
    precision_dict = dict()
    recall_dict = dict()
    f1_score_dict = dict()
    support_dict = dict()
    for cr in classification_reports:
        for category,result in cr.items():
            if category == "accuracy":
                accuracy_list.append(result)
            elif category in precision_dict:
                precision_dict[category].append(result['precision'])
                recall_dict[category].append(result['recall'])
                f1_score_dict[category].append(result['f1-score'])
                support_dict[category].append(result['support'])
            else:
                precision_dict[category] = [result['precision']]
                recall_dict[category] = [result['recall']]
                f1_score_dict[category] = [result['f1-score']]
                support_dict[category] = [result['support']]
    precision = pd.DataFrame(precision_dict)
    recall = pd.DataFrame(recall_dict)
    f1_score = pd.DataFrame(f1_score_dict)
    support = pd.DataFrame(support_dict)

    # Plot results
    print(f"{name} - Plotting kfold classification reports")
    plt.clf()
    fig, axes = plt.subplots(nrows=3,ncols=1,figsize=(18,10))
    sns.stripplot(precision, ax = axes[0], orient='h')
    axes[0].set_xlim([-0.025, 1.025])
    axes[0].set_title("Precision");
    axes[0].grid(True, axis='y')
    sns.stripplot(recall, ax = axes[1], orient='h')
    axes[1].set_title("Recall");
    axes[1].set_xlim([-0.025, 1.025])
    axes[1].grid(True, axis='y')
    sns.stripplot(f1_score, ax = axes[2], orient='h')
    axes[2].set_title("F1 score");
    axes[2].set_xlim([-0.025, 1.025])
    axes[2].grid(True, axis='y')
    plt.savefig(REPORT_MEDIA_FOLDER / "packet_pincer_train_models_{name}_kfold.png", bbox_inches="tight")

def grid_search_run(df_train: pd.DataFrame, skf: StratifiedKFold, name: str, model, params):
    print(f"{name} - Grid search validation run")

    x_train = df_train.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_train = df_train.loc[: , df_train.columns == PACKET_PINCER_LABEL]

    print(f"{name} - Preparing grid search")
    knn_grid_search = GridSearchCV(model, param_grid=params, scoring=['f1_macro','f1_weighted'], refit='f1_macro', cv=skf, n_jobs=-1, verbose=1)

    print(f"{name} - Executing search. Start time at {datetime.now()}")
    start_time = datetime.now()
    knn_grid_search.fit(x_train, y_train.values.ravel())
    elapsed_time = datetime.now() - start_time
    print(f"{name} - Best Params={knn_grid_search.best_params_}, f1_weighted={knn_grid_search.best_score_}, The search took {elapsed_time}.")

    print(f"{name} - Dumping results")
    joblib.dump(knn_grid_search, TMP_FOLDER / f"{name}_grid_search.joblib")

    return knn_grid_search

def train_run(df_train: pd.DataFrame, df_test: pd.DataFrame, skf: StratifiedKFold, name: str, model):
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
    with open(TMP_FOLDER / "{name}_classification_report.json", "w") as write_file:
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
    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_models_{name}.png", bbox_inches="tight")
    print(clasification_report)

def naive_bayes(df_train: pd.DataFrame, df_test: pd.DataFrame, skf: StratifiedKFold):
    cross_validation_run(df_train, df_test, skf, "Naive bayes", GaussianNB())
    train_run(df_train, df_test, skf, "Naive bayes", GaussianNB())

def knn(df_train: pd.DataFrame, df_test: pd.DataFrame, skf: StratifiedKFold):
    name="KNN"

    grid_search = grid_search_run(df_train, skf, name, KNeighborsClassifier(), {'n_neighbors':list(range(1,30,2)), 'weights':('distance','uniform')}) 

    print(f"{name} - Plotting results")
    results = pd.DataFrame(grid_search.cv_results_)
    f1_weighted_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_n_neighbors)|(param_weights)|(split[0-9]+_test_f1_weighted)$')\
        .melt(id_vars=["param_n_neighbors", "param_weights","mean_fit_time", "mean_score_time"], value_name='f1_weighted')\
        .drop(labels="variable", axis=1)

    f1_macro_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_n_neighbors)|(param_weights)|(split[0-9]+_test_f1_macro)$')\
        .melt(id_vars=["param_n_neighbors", "param_weights","mean_fit_time", "mean_score_time"], value_name='f1_macro')\
        .drop(labels="variable", axis=1)
    
    fig, axes = plt.subplots(nrows=1,ncols=4,figsize=(24,6))
    sns.scatterplot(ax=axes[0], data=f1_weighted_scores, style='param_weights',x="param_n_neighbors", y="f1_weighted", hue="param_weights")
    sns.lineplot(ax=axes[0], data=results, style='param_weights',x="param_n_neighbors", y="mean_test_f1_weighted", hue="param_weights")
    sns.scatterplot(ax=axes[1], data=f1_macro_scores, style='param_weights',x="param_n_neighbors", y="f1_macro", hue="param_weights")
    sns.lineplot(ax=axes[1], data=results, style='param_weights',x="param_n_neighbors", y="mean_test_f1_macro", hue="param_weights")
    axes[1].legend(loc='lower left')
    sns.lineplot(ax=axes[2], data=f1_weighted_scores, style='param_weights',x="param_n_neighbors", y="mean_fit_time", hue="param_weights")
    sns.lineplot(ax=axes[3], data=f1_weighted_scores, style='param_weights',x="param_n_neighbors", y="mean_score_time", hue="param_weights")
    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_models_{name}_gridsearch.png", bbox_inches="tight")

    train_run(df_train, df_test, skf, "KNN", KNeighborsClassifier(**grid_search.best_params_))

def decision_trees(df_train: pd.DataFrame, df_test: pd.DataFrame, skf: StratifiedKFold):
    name="decision_trees"

    grid_search = grid_search_run(df_train, skf, name, DecisionTreeClassifier(), {
        'criterion': ('gini', 'entropy', 'log_loss'),
        'min_impurity_decrease': list(np.linspace(0,0.5,21)),
        'min_samples_split':list(range(3,30,3))
    }) 

    train_run(df_train, df_test, skf, name, DecisionTreeClassifier(**grid_search.best_params_))


def main() -> None:
    df_train, df_test, scaler, skf = read_files()
    naive_bayes(df_train, df_test, skf)
    knn(df_train, df_test, skf)
    decision_trees(df_train, df_test, skf)

if __name__=="__main__":
    main()
