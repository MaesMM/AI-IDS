#!/usr/bin/env python3
import csv
import os

csv_path = "/home/maes/sandbox/snortdev/model/datasets/httpParamsDataset/complete.csv"  # Path to your CSV file
datasetName = "complete"                                     # Wanted name of the outputed dataset directory

label = {0:"anom",1:"norm"}
train_ratio = 0.7
payload_column_nrb = 0
label_column_nbr = 1

os.makedirs("./datasets/"+datasetName+"/train/malicious", exist_ok=True)
os.makedirs("./datasets/"+datasetName+"/train/benin", exist_ok=True)
os.makedirs("./datasets/"+datasetName+"/test/malicious", exist_ok=True)
os.makedirs("./datasets/"+datasetName+"/test/benin", exist_ok=True)

with open(csv_path, newline='', encoding="utf-8") as f:
    datareader = csv.reader(f, delimiter=',', quotechar='"')
    ncol = len(next(datareader))
    f.seek(0)  
    headers = next(datareader) 
    rows = list(datareader)

num_train = int(len(rows) * train_ratio)

# Train split
for idx, row in enumerate(rows[:num_train]):
    file_dir = None
    if row[label_column_nbr] == label[0]:
        file_dir = "./datasets/"+ datasetName +"/train/malicious"
    elif row[label_column_nbr] == label[1]:
        file_dir = "./datasets/"+ datasetName +"/train/benin"
    else:
        print(f"Row {idx} has unknown label '{row[label_column_nbr]}'. Skipping.")
        continue

    file_name = os.path.join(file_dir, f"{idx}.txt")
    try:
        with open(file_name, "w", encoding="utf-8") as out_file:
            out_file.write(row[payload_column_nrb])
        print(f"Wrote {file_name}")
    except Exception as e:
        print(f"Failed to write {file_name}: {e}")


# Test split
for idx, row in enumerate(rows[num_train:]):
    file_dir = None
    if row[label_column_nbr] == label[0]:
        file_dir = "./datasets/"+ datasetName +"/test/malicious"
    elif row[label_column_nbr] == label[1]:
        file_dir = "./datasets/"+ datasetName +"/test/benin"
    else:
        print(f"Row {idx} has unknown label '{row[label_column_nbr]}'. Skipping.")
        continue

    file_name = os.path.join(file_dir, f"{idx}.txt")
    try:
        with open(file_name, "w", encoding="utf-8") as out_file:
            out_file.write(row[payload_column_nrb])
        print(f"Wrote {file_name}")
    except Exception as e:
        print(f"Failed to write {file_name}: {e}")

