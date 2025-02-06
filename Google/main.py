#!/usr/bin/env python3

from dataProcess import *
from model import *
import os, sys
import pandas as pd
import numpy as np
import tensorflow as tf


def main():
        # csv_file = sys.argv[1]
    if len(sys.argv) > 2:
        verbose = sys.argv[2]
    else:
        verbose = None
        
    cwd = os.getcwd()
    csv_file = '/home/maes/sandbox/snortdev/datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
    df = pd.read_csv(csv_file)

    # df = pd.read_csv("hf://datasets/scikit-learn/credit-card-clients/UCI_Credit_Card.csv")

    if(verbose):
        df.head()

    excluded_labels_list = ["Flow ID", "Timestamp", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"]
    cleaned_features = clean_dataset(df, excluded_labels_list)
    if(verbose):
        print(cleaned_features)
        print(f"DF.HEAD: {cleaned_features.head(0)}, EOF")


    X_train, X_test, y_train, y_test = preprocess_dataset(cleaned_features, label='vpn')

    model = create_model(len(X_train.columns))

    X_train.replace([np.inf, -np.inf], np.finfo(np.float16).max, inplace=True)
    
    # X_train = tf.convert_to_tensor(X_train, dtype=tf.float16)
    # X_test = tf.convert_to_tensor(X_test, dtype=tf.float16)
    # Replace infinite values with a large finite number (e.g., max float)
        

    print(f"check for NAN value: {cleaned_features.isnull().sum()} FIN_NAN")  # Check for NaN values

    print("Check for NaN values in X_train:", np.isnan(X_train).any())
    print("Check for infinite values in X_train:", np.isinf(X_train).any())
    print("Check for NaN values in y_train:", np.isnan(y_train).any())
    print("Check for infinite values in y_train:", np.isinf(y_train).any())

    train_model(model, X_train, y_train)

    accuracy = model.evaluate(x=X_test, y=y_test, verbose=2)
    y_pred = model.predict(X_test)


if(__name__ == "__main__"):
    main()