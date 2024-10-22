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

def read_files() -> Tuple[pd.DataFrame, pd.DataFrame, MinMaxScaler, StratifiedKFold]:
    df_train = pd.read_csv(TRAIN_CSV)
    df_validation = pd.read_csv(VALIDATION_CSV)

    return (df_train, df_validation)

def grid_search_run(df_train: pd.DataFrame, name: str, model, params):
    print(f"{name} - Grid search validation run")

    x_train = df_train.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_train = df_train.loc[: , df_train.columns == PACKET_PINCER_LABEL]

    print(f"{name} - Preparing grid search")
    knn_grid_search = GridSearchCV(model, param_grid=params, scoring=['f1_macro', 'f1_weighted'], refit='f1_macro', n_jobs=-1, verbose=1, cv=StratifiedKFold())

    print(f"{name} - Executing search. Start time at {datetime.now()}")
    start_time = datetime.now()
    knn_grid_search.fit(x_train, y_train.values.ravel())
    elapsed_time = datetime.now() - start_time
    print(f"{name} - Best Params={knn_grid_search.best_params_}, f1_macro={knn_grid_search.best_score_}, The search took {elapsed_time}.")

    print(f"{name} - Dumping results")
    joblib.dump(knn_grid_search, TMP_FOLDER / f"{name}_grid_search.joblib")

    return knn_grid_search

def train_run(df_train: pd.DataFrame, df_validation: pd.DataFrame, name: str, model):
    print(f"{name} - Full train run")

    x_train = df_train.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_train = df_train.loc[: , df_train.columns == PACKET_PINCER_LABEL]

    x_test = df_validation.loc[: , df_train.columns != PACKET_PINCER_LABEL]
    y_test = df_validation.loc[: , df_train.columns == PACKET_PINCER_LABEL]

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

def naive_bayes(df_train: pd.DataFrame, df_validation: pd.DataFrame):
    train_run(df_train, df_validation, "Naive bayes", GaussianNB())

def knn(df_train: pd.DataFrame, df_validation: pd.DataFrame):
    name="KNN"

    grid_search = grid_search_run(df_train, name, KNeighborsClassifier(), {
        'n_neighbors':list(range(1,30,6)), 
        'weights':('distance','uniform')
    })

    # Plot
    print(f"{name} - Reformating results")
    results = pd.DataFrame(grid_search.cv_results_)
    f1_weighted_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_n_neighbors)|(param_weights)|(split[0-9]+_test_f1_weighted)$')\
        .melt(id_vars=["param_n_neighbors", "param_weights","mean_fit_time", "mean_score_time"], value_name='f1_weighted')\
        .drop(labels="variable", axis=1)

    f1_macro_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_n_neighbors)|(param_weights)|(split[0-9]+_test_f1_macro)$')\
        .melt(id_vars=["param_n_neighbors", "param_weights","mean_fit_time", "mean_score_time"], value_name='f1_macro')\
        .drop(labels="variable", axis=1)
    
    print(f"{name} - Plotting results")
    fig, axes = plt.subplots(nrows=1,ncols=4,figsize=(24,6))
    sns.scatterplot(ax=axes[0], data=f1_weighted_scores, style='param_weights',x="param_n_neighbors", y="f1_weighted", hue="param_weights")
    sns.lineplot(ax=axes[0], data=results, style='param_weights',x="param_n_neighbors", y="mean_test_f1_weighted", hue="param_weights")
    sns.scatterplot(ax=axes[1], data=f1_macro_scores, style='param_weights',x="param_n_neighbors", y="f1_macro", hue="param_weights")
    sns.lineplot(ax=axes[1], data=results, style='param_weights',x="param_n_neighbors", y="mean_test_f1_macro", hue="param_weights")
    axes[1].legend(loc='lower left')
    sns.lineplot(ax=axes[2], data=f1_weighted_scores, style='param_weights',x="param_n_neighbors", y="mean_fit_time", hue="param_weights")
    sns.lineplot(ax=axes[3], data=f1_weighted_scores, style='param_weights',x="param_n_neighbors", y="mean_score_time", hue="param_weights")
    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_models_{name}_gridsearch.png", bbox_inches="tight")

    train_run(df_train, df_validation, "KNN", KNeighborsClassifier(**grid_search.best_params_))

    return grid_search.best_params_

def decision_trees(df_train: pd.DataFrame, df_validation: pd.DataFrame):
    name="decision_trees"

    grid_search = grid_search_run(df_train, name, DecisionTreeClassifier(), {
        'criterion': ('gini', 'entropy', 'log_loss'),
        'min_impurity_decrease': list(np.linspace(0,0.5,21)),
        'min_samples_split': list(range(3,30,3)),
    })

    train_run(df_train, df_validation, name, DecisionTreeClassifier(**grid_search.best_params_))

    # Plot
    print(f"{name} - Reformating results")
    results = pd.DataFrame(grid_search.cv_results_)
    f1_weighted_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_min_impurity_decrease)|(param_min_samples_split)|(split[0-9]+_test_f1_weighted)$')\
                        .melt(id_vars=["mean_fit_time", "mean_score_time", "param_min_impurity_decrease", "param_min_samples_split"], value_name='f1_weighted')\
                        .drop(labels="variable", axis=1)
    f1_macro_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_min_impurity_decrease)|(param_min_samples_split)|(split[0-9]+_test_f1_macro)$')\
                        .melt(id_vars=["mean_fit_time", "mean_score_time", "param_min_impurity_decrease", "param_min_samples_split"], value_name='f1_macro')\
                        .drop(labels="variable", axis=1)
    
    print(f"{name} - Plotting results")
    plt.clf()
    sns.jointplot(data=f1_weighted_scores, x="param_min_impurity_decrease", y="param_min_samples_split", hue="f1_weighted")
    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_models_{name}_gridsearch_f1_weighted.png", bbox_inches="tight")

    plt.clf()
    sns.jointplot(data=f1_macro_scores, x="param_min_impurity_decrease", y="param_min_samples_split", hue="f1_macro")
    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_models_{name}_gridsearch_f1_macro.png", bbox_inches="tight")

    return grid_search.best_params_

def nn(df_train: pd.DataFrame, df_validation: pd.DataFrame):
    name="nn"

    grid_search = grid_search_run(df_train, name, MLPClassifier(max_iter=1000), {
        'activation': ("relu", "tanh", "logistic"),
        'hidden_layer_sizes': ((70, 30, 5), (50, 50, 50), (70, 70, 70), (70, 70, 70, 15), (70, 70, 70, 1))
    })

    # Plot
    print(f"{name} - Reformating results")
    results = pd.DataFrame(grid_search.cv_results_)
    f1_weighted_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_activation)|(param_hidden_layer_sizes)|(split[0-9]+_test_f1_weighted)$')\
                        .melt(id_vars=["mean_fit_time", "mean_score_time", "param_activation", "param_hidden_layer_sizes"], value_name='f1_weighted')\
                        .drop(labels="variable", axis=1)
    f1_macro_scores = results.filter(regex=r'^(mean_fit_time)|(mean_score_time)|(param_activation)|(param_hidden_layer_sizes)|(split[0-9]+_test_f1_macro)$')\
                        .melt(id_vars=["mean_fit_time", "mean_score_time", "param_activation", "param_hidden_layer_sizes"], value_name='f1_macro')\
                        .drop(labels="variable", axis=1)
    
    print(f"{name} - Results:")
    print(f1_weighted_scores)
    print(f1_macro_scores)

    train_run(df_train, df_validation, name, MLPClassifier(max_iter=1000, **grid_search.best_params_))

    return grid_search.best_params_

def svm(df_train: pd.DataFrame, df_validation: pd.DataFrame):
    name="svm"

    grid_search = grid_search_run(df_train, name, SVC(),  [
        {'kernel':['linear'], 'C':np.logspace(-1, 6, num=8, base=10.0)},
        {'kernel':['poly'], 'C':np.logspace(-1, 6, num=8, base=10.0), 'degree': (2,3)},
        {'kernel':['rbf'], 'C':np.logspace(-1, 6, num=8, base=10.0), 'gamma': np.logspace(-6, 1, num=8, base=10.0)},
    ])

    train_run(df_train, df_validation, name, SVC(**grid_search.best_params_))

    # Plot results
    results = pd.DataFrame(grid_search.cv_results_)

    fig, axes = plt.subplots(nrows=2,ncols=3,figsize=(18,12))

    # Weighted + linear
    cell_scores = results[results.param_kernel == 'linear']\
                    .filter(regex=r'^(param_C)|(mean_test_f1_weighted)|(split[0-9]+_test_f1_weighted)$')\
                    .melt(id_vars=["param_C", "mean_test_f1_weighted"], value_name='f1_weighted')\
                    .drop(labels="variable", axis=1)

    sns.scatterplot(ax=axes[0, 0], data=cell_scores, x="param_C", y="f1_weighted")
    sns.lineplot(ax=axes[0, 0], data=cell_scores, x="param_C", y="mean_test_f1_weighted")
    axes[0, 0].set_title('Linear SVM weighted scores')
    axes[0, 0].set_xscale('log')
    axes[0, 0].set_ylim([0.94, 1])

    # Macro + linear
    cell_scores = results[results.param_kernel == 'linear']\
                    .filter(regex=r'^(param_C)|(mean_test_f1_macro)|(split[0-9]+_test_f1_macro)$')\
                    .melt(id_vars=["param_C", "mean_test_f1_macro"], value_name='f1_macro')\
                    .drop(labels="variable", axis=1)

    sns.scatterplot(ax=axes[1, 0], data=cell_scores, x="param_C", y="f1_macro")
    sns.lineplot(ax=axes[1, 0], data=cell_scores, x="param_C", y="mean_test_f1_macro")
    axes[1, 0].set_title('Linear SVM macro scores')
    axes[1, 0].set_xscale('log')
    axes[1, 0].set_ylim([0.1, 0.65])

    # Weighted + polinomic
    cell_scores = results[results.param_kernel == 'poly']\
                    .filter(regex=r'^(param_C)|(param_degree)|(mean_test_f1_weighted)|(split[0-9]+_test_f1_weighted)$')\
                    .melt(id_vars=["param_C", "param_degree", "mean_test_f1_weighted"], value_name='f1_weighted')\
                    .drop(labels="variable", axis=1)

    sns.scatterplot(ax=axes[0, 1], data=cell_scores, x="param_C", y="f1_weighted", style='param_degree', hue='param_degree')
    sns.lineplot(ax=axes[0, 1], data=cell_scores, x="param_C", y="mean_test_f1_weighted", style='param_degree', hue='param_degree')
    axes[0, 1].set_title('Polinomic SVM weighted scores')
    axes[0, 1].set_xscale('log')
    axes[0, 1].set_ylim([0.94, 1])

    # Macro + polinomic
    cell_scores = results[results.param_kernel == 'poly']\
                    .filter(regex=r'^(param_C)|(param_degree)|(mean_test_f1_macro)|(split[0-9]+_test_f1_macro)$')\
                    .melt(id_vars=["param_C", "param_degree", "mean_test_f1_macro"], value_name='f1_macro')\
                    .drop(labels="variable", axis=1)

    sns.scatterplot(ax=axes[1, 1], data=cell_scores, x="param_C", y="f1_macro", style='param_degree', hue='param_degree')
    sns.lineplot(ax=axes[1, 1], data=cell_scores, x="param_C", y="mean_test_f1_macro", style='param_degree', hue='param_degree')
    axes[1, 1].set_title('Polinomic SVM macro scores')
    axes[1, 1].set_xscale('log')
    axes[1, 1].set_ylim([0.1, 0.65])

    # Weighted + rbf
    cell_scores = results[results.param_kernel == 'rbf']\
                    [["param_C", "param_gamma", "mean_test_f1_weighted"]]\
                .pivot_table(columns='param_C', index='param_gamma', values='mean_test_f1_weighted')
    sns.heatmap(cell_scores, square=True, annot=True, cmap='Blues', cbar=False, ax=axes[0, 2], fmt='.3g')
    axes[0, 2].set_title('RBF SVM weighted scores')

    # Macro + rbf
    cell_scores = results[results.param_kernel == 'rbf']\
                    [["param_C", "param_gamma", "mean_test_f1_macro"]]\
                .pivot_table(columns='param_C', index='param_gamma', values='mean_test_f1_macro')
    sns.heatmap(cell_scores, square=True, annot=True, cmap='Blues', cbar=False, ax=axes[1, 2], fmt='.3g')
    axes[1, 2].set_title('RBF SVM macro scores')

    plt.savefig(REPORT_MEDIA_FOLDER / f"packet_pincer_train_models_{name}_gridsearch", bbox_inches="tight")

    return grid_search.best_params_

def voting_classifier(df_train: pd.DataFrame, df_validation: pd.DataFrame, knn_params, dt_params, nn_params): 
    name = "voting_classifier"

    grid_search = grid_search_run(df_train, name,
        VotingClassifier(estimators=[
            ('nb', GaussianNB()),
            ('knn', KNeighborsClassifier(**knn_params)),
            ('dt', DecisionTreeClassifier(**dt_params)),
            ('mlp',  MLPClassifier(max_iter=1000, **nn_params)),
        ]),                          
        {
            'voting': ('hard','soft')
        }
    )

    train_run(df_train, df_validation, name, VotingClassifier(estimators=[
            ('nb', GaussianNB()),
            ('knn', KNeighborsClassifier(**knn_params)),
            ('dt', DecisionTreeClassifier(**dt_params)),
            ('mlp',  MLPClassifier(max_iter=1000, **nn_params)),
    ], **grid_search.best_params_))

def bagging(df_train: pd.DataFrame, df_validation: pd.DataFrame): 
    name = "bagging"

    grid_search = grid_search_run(df_train, name,
        BaggingClassifier(estimator=DecisionTreeClassifier()),                          
        {
            'n_estimators': [1,2,5,10,20,50,100,200,300],
            'max_features': [1, 0.35]
        }
    )

    train_run(df_train, df_validation, name, BaggingClassifier(estimator=DecisionTreeClassifier(), **grid_search.best_params_))

def random_forest(df_train: pd.DataFrame, df_validation: pd.DataFrame,): 
    name = "random_forest"

    grid_search = grid_search_run(df_train, name,
        RandomForestClassifier(),                          
        {
            'n_estimators': [1,2,5,10,20,50,100,200],
        }
    )

    train_run(df_train, df_validation, name, RandomForestClassifier(**grid_search.best_params_))

def extra_trees(df_train: pd.DataFrame, df_validation: pd.DataFrame): 
    name = "extra_trees"

    grid_search = grid_search_run(df_train, name,
        ExtraTreesClassifier(),                          
        {
            'n_estimators': [1,2,5,10,20,50,100,200],
        }
    )

    train_run(df_train, df_validation, name, ExtraTreesClassifier(**grid_search.best_params_))

def adaboost(df_train: pd.DataFrame, df_validation: pd.DataFrame): 
    name = "adaboost"

    grid_search = grid_search_run(df_train, name,
        AdaBoostClassifier(),                          
        {
            'n_estimators': [1,2,5,10,20,50,100,200],
        }
    )

    train_run(df_train, df_validation, name, AdaBoostClassifier(**grid_search.best_params_))


def main() -> None:
    df_train, df_validation = read_files()
    
    naive_bayes(df_train, df_validation)
    knn_params = knn(df_train, df_validation)
    dt_params = decision_trees(df_train, df_validation)
    nn_params = nn(df_train, df_validation)
    voting_classifier(df_train, df_validation, knn_params, dt_params, nn_params)
    bagging(df_train, df_validation)
    random_forest(df_train, df_validation)
    extra_trees(df_train, df_validation)
    adaboost(df_train, df_validation)


if __name__=="__main__":
    main()
