import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib

packet_csv_path = 'packetdataset.csv'
dataset_folder_path = 'datasets'
model_save_path = 'packet_detection_model.pkl'

def load_packet_csv():
    df = pd.read_csv(packet_csv_path)
    
    df = df.dropna(axis=1)
    
    df['bad_packet'] = df['bad_packet'].astype(int)
    
    return df

def load_additional_datasets():
    dataframes = []
    
    for file in os.listdir(dataset_folder_path):
        if file.endswith(".csv"):
            file_path = os.path.join(dataset_folder_path, file)
            print("processing file:", file_path)
            
            df = pd.read_csv(file_path, delimiter="|")
            
            df = df[['id.orig_h', 'id.resp_h', 'proto', 'id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes', 'label']]
            df['bad_packet'] = df['label'].apply(lambda x: 1 if x == "Malicious" else 0)
            dataframes.append(df)
    
    combined_df = pd.concat(dataframes, ignore_index=True)
    
    return combined_df

def preprocess_data():
    print("\npreprocessing")
    df_main = load_packet_csv()
    df_additional = load_additional_datasets()

    df_main = df_main.rename(columns={
        'Source': 'id.orig_h',
        'Destination': 'id.resp_h',
        'Protocol': 'proto',
        'Source Port': 'id.orig_p',
        'Destination Port': 'id.resp_p',
        'Length': 'orig_bytes'
    })
    df_main['resp_bytes'] = 0

    # combine datasets
    df = pd.concat([df_main, df_additional], ignore_index=True)
    
    df = df[['id.orig_h', 'id.resp_h', 'proto', 'id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes', 'bad_packet']].fillna(0)
    
    # drop bad entries
    for column in ['id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes']:
        df[column] = pd.to_numeric(df[column], errors='coerce')
    df = df.dropna()
    
    source_ips_ports = set(zip(df['id.orig_h'], df['id.orig_p']))
    dest_ips_ports = set(zip(df['id.resp_h'], df['id.resp_p']))
    joblib.dump((source_ips_ports, dest_ips_ports), 'training_ips_ports.pkl')
    
    label_encoder_ip_src = LabelEncoder()
    label_encoder_ip_dst = LabelEncoder()
    label_encoder_proto = LabelEncoder()
    
    df['id.orig_h'] = label_encoder_ip_src.fit_transform(df['id.orig_h'])
    df['id.resp_h'] = label_encoder_ip_dst.fit_transform(df['id.resp_h'])
    df['proto'] = label_encoder_proto.fit_transform(df['proto'])

    joblib.dump(label_encoder_ip_src, 'label_encoder_ip_src.pkl')
    joblib.dump(label_encoder_ip_dst, 'label_encoder_ip_dst.pkl')
    joblib.dump(label_encoder_proto, 'label_encoder_proto.pkl')

    X = df.drop(columns=['bad_packet'])
    y = df['bad_packet']
    
    return X, y

def train_and_save_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print("training set shape:", X_train.shape)
    print("test set shape:", X_test.shape)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"accuracy: {accuracy:.2f}")

    joblib.dump(model, model_save_path)
    print(f"model saved to {model_save_path}")

if __name__ == "__main__":
    print("starting model training")
    X, y = preprocess_data()
    train_and_save_model(X, y)
    print("model training done")
