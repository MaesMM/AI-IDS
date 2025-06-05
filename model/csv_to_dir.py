import csv
import os

csv_path = "/home/maes/sandbox/snortdev/model/datasets/httpParamsDataset/payload_full.csv"
label = {0:"anom",1:"norm"}
train_ratio = 0.7
payload_column_nrb = 0
label_column_nbr = 3
datasetName = "LeTest"



os.makedirs("./datasets/"+datasetName+"/train/neg", exist_ok=True)
os.makedirs("./datasets/"+datasetName+"/train/pos", exist_ok=True)
os.makedirs("./datasets/"+datasetName+"/test/neg", exist_ok=True)
os.makedirs("./datasets/"+datasetName+"/test/pos", exist_ok=True)

with open(csv_path, newline='', encoding="utf-8") as f:
    datareader = csv.reader(f, delimiter=',', quotechar='"')

    ncol = len(next(datareader))
    f.seek(0)  
    headers = next(datareader) 

    rows = list(datareader)


num_train = int(len(rows) * train_ratio)

for idx, row in enumerate(rows[:num_train]):
    # if len(row) < ncol:
    #     print(f"Skipping row {idx} due to insufficient columns: {row}")
    #     continue


    file_dir = None
    if row[3] == label[0]:
        file_dir = "./datasets/"+datasetName+"/train/neg"
    elif row[3] == label[1]:
        file_dir = "./datasets/"+datasetName+"/train/pos"
    else:
        print(f"Row {idx} has unknown label '{row[3]}'. Skipping.")
        continue

    file_name = os.path.join(file_dir, f"{idx}.txt")
    try:
        with open(file_name, "w", encoding="utf-8") as out_file:
            out_file.write(row[0])
        print(f"Wrote {file_name}")
    except Exception as e:
        print(f"Failed to write {file_name}: {e}")


for idx, row in enumerate(rows[num_train:]):
    # if len(row) < ncol:
    #     print(f"Skipping row {idx} due to insufficient columns: {row}")
    #     continue


    file_dir = None
    if row[3] == label[0]:
        file_dir = "./datasets/"+datasetName+"/test/neg"
    elif row[3] == label[1]:
        file_dir = "./datasets/"+datasetName+"/test/pos"
    else:
        print(f"Row {idx} has unknown label '{row[3]}'. Skipping.")
        continue

    file_name = os.path.join(file_dir, f"{idx}.txt")
    try:
        with open(file_name, "w", encoding="utf-8") as out_file:
            out_file.write(row[0])
        print(f"Wrote {file_name}")
    except Exception as e:
        print(f"Failed to write {file_name}: {e}")