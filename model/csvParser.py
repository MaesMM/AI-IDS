import csv
DATASET_SIZE = 100000

def load_csv_to_array(csv_file):
    data = [DATASET_SIZE]
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)

        for i, row in enumerate(reader):
            attack_value = 0 if row[-1].lower() == 'benign' else 1          # Label: 0=Begnin, 1=Attack 
            # params = [element for element in row[:-1]]
            params = [row[:-1]]
            input_param_line = (params, attack_value)
            data.append(input_param_line)
        
    return data
