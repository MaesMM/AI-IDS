#!/usr/bin/env python3

from dataProcess import *
from model import *
import os, sys, argparse
import pandas as pd
import numpy as np
import tensorflow as tf


def main():
    parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')
    
    parser.add_argument('-v','--verbose', help='More verbosity for debug', action='store_true')
    parser.add_argument('-d', '--dataset', help='Path of the input Dataset in csv format', required=True)
    parser.add_argument('-o', '--output', help ='Name of the saved model. Save the model in a .keras archive if specified')
    parser.add_argument('-l', '--label', help = 'Specify the dataset label to be begnin/safe/0, begnin by default')
    args = parser.parse_args()
    verbose = args.verbose
    outputName = args.output

    df = pd.read_csv(args.dataset)
    # df = pd.read_csv("hf://datasets/scikit-learn/credit-card-clients/UCI_Credit_Card.csv")

    if(verbose):
        df.head()

    excluded_labels_list = ["Flow ID", "Timestamp", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"]
    cleaned_features = clean_dataset(df, excluded_labels_list, verbose=verbose)
    if(verbose):
        print(cleaned_features)
        print(f"DF.HEAD: {cleaned_features.head(0)}, EOF")

    X_train, X_test, y_train, y_test = preprocess_dataset(cleaned_features, label=args.label, verbose=verbose)

    model = create_model(len(X_train.columns))

    X_train.replace([np.inf, -np.inf], np.finfo(np.float16).max, inplace=True)
            
    if verbose:
        print("Check for NaN values in X_train:", np.isnan(X_train).any())
        print("Check for infinite values in X_train:", np.isinf(X_train).any())
        print("Check for NaN values in y_train:", np.isnan(y_train).any())
        print("Check for infinite values in y_train:", np.isinf(y_train).any())

    train_model(model, X_train, y_train)

    model.evaluate(x=X_test, y=y_test, verbose=2)
    if (outputName is not None):
        print(f"saving the trained model to models/{outputName}.keras") if verbose else None
        model.save(f"models/{outputName}.keras")

if(__name__ == "__main__"):
    main()