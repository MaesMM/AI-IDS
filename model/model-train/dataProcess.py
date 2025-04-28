import pandas    as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import socket, struct


def ip_to_decimal(ip):
    packed_ip = socket.inet_pton(socket.AF_INET, ip)
    return struct.unpack("!I", packed_ip)[0]

def ipv4_to_int(ipv4_address: str) -> int:
    octets = ipv4_address.split('.')
    return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])


def clean_dataset(df, labels_to_exclude, threshold_null=0.9, remove_duplicates=True, verbose=False):
    print("Shape original:", df.shape) if verbose else None

    cleaned_df = df.copy()

    # Delete the 'labels_to_exclude' columns 
    for label in labels_to_exclude:
        cleaned_df = cleaned_df.drop(columns=[col for col in cleaned_df.columns if label in col])
        print(f"Colonnes contenant '{label}' supprimées.") if verbose else None

    # Convert IPv4 adress to Integer value
    ip_column = [col for col in cleaned_df.columns if 'ip' in col.lower()]
    if ip_column:
        for ip_label in ip_column:
            cleaned_df[ip_label] = cleaned_df[ip_label].apply(ipv4_to_int)
            currentIp = cleaned_df.columns
    else:
        print("No column named 'ip' found.") if verbose else None

    # Suppression des doublons
    if remove_duplicates:
        initial_rows = len(cleaned_df)
        cleaned_df = cleaned_df.drop_duplicates()
        print("Lignes dupliquées supprimées:", initial_rows - len(cleaned_df)) if verbose else None
    if(verbose):
        print("\nShape final:", cleaned_df.shape)
        print("\nDistribution des labels après nettoyage:")

    return cleaned_df

git 
def preprocess_dataset(df, test_size=0.2, random_state=89, label: str = 'benign' ,verbose=True):
    if not (df.iloc[:, -1].apply(type).isin([int, str]).all()):
        raise Exception("Data labels can have only two different values and be either strings or booleans") 
    elif df.iloc[:, -1].apply(type).eq(str).all():
        labels = (df.iloc[:, -1].str.lower() != label).astype(int)

    features_df = df.iloc[:, :-1]

    features_df = features_df.fillna(0)
    X_train, X_test, y_train, y_test = train_test_split(
        features_df,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels  # Assure une distribution équilibrée des classes
    )

    if(verbose):
        print("Forme du jeu d'entraînement:", X_train.shape)
        print("Forme du jeu de test:", X_test.shape)
        print("\nDistribution des classes dans l'ensemble d'entraînement:")
        print(y_train.value_counts(normalize=True))
        print("\nDistribution des classes dans l'ensemble de test:")
        print(y_test.value_counts(normalize=True))

    return X_train, X_test, y_train, y_test



