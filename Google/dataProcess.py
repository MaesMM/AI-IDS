import pandas    as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
# from IPython.display import display
import socket, struct

def clean_dataset(df, labels_to_exclude, threshold_null=0.9, remove_duplicates=True, verbose=False):
    print("Shape original:", df.shape)

    cleaned_df = df.copy()

    # 2. Suppression des colonnes en fonction du nom de la colonne issue de la liste labels et convertion des adresses en hexadecimal
    for label in labels_to_exclude:
        cleaned_df = cleaned_df.drop(columns=[col for col in cleaned_df.columns if label in col])
        print(f"Colonnes contenant '{label}' supprimées.")
        # if (label.lower() == 'ip'):
        #     cleaned_df[label] = cleaned_df[label].apply(ip_to_hex)

    ip_column = [col for col in cleaned_df.columns if 'ip' in col.lower()]
    if ip_column:
        for ip_label in ip_column:
            cleaned_df[ip_label] = cleaned_df[ip_label].apply(ipv4_to_int)
            # cleaned_df[ip_label] = cleaned_df[ip_label].str.split('.').apply(lambda x: list(map(int, x)))
            currentIp = cleaned_df.columns
            # print(f"DEBUG{ip_label}")
            # columnIndex = df.columns.get_loc(ip_label)
            # for i in range(4):
                # cleaned_df.insert(columnIndex + i, ip_label+str(i), getIp(IP, i))
            
    else:
        print("No column named 'ip' found.")

    # 3. Suppression des doublons
    if remove_duplicates:
        initial_rows = len(cleaned_df)
        cleaned_df = cleaned_df.drop_duplicates()
        print("Lignes dupliquées supprimées:", initial_rows - len(cleaned_df))
    if(verbose):
        print("\nShape final:", cleaned_df.shape)
        print("\nDistribution des labels après nettoyage:")

    return cleaned_df

def ip_to_decimal(ip):
    packed_ip = socket.inet_pton(socket.AF_INET, ip)
    print(type(struct.unpack("!I", packed_ip)[0]))
    return struct.unpack("!I", packed_ip)[0]

def ipv4_to_int(ipv4_address: str) -> int:
    octets = ipv4_address.split('.')
    return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])

def preprocess_dataset(df, test_size=0.2, random_state=89, label: str = 'benign' ,verbose=True):
    labels = (df.iloc[:, -1].str.lower() != label).astype(int)
    features_df = df.iloc[:, :-1]

    # 1. Gestion des valeurs manquantes
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



