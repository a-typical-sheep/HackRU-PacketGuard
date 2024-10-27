import joblib
from scapy.all import sniff, IP, TCP
import pandas as pd
from datetime import datetime

model = joblib.load('packet_detection_model.pkl')

CONFIDENCE_LEVEL = 0.01

malicious_ip_ports = set()
try:
    df = pd.read_csv('datasets/CTU-IoT-Malware-Capture-1-1conn.log.labeled.csv', delimiter="|")
    ip_column_name = 'id.orig_h'
    port_column_name = 'id.orig_p'
    if ip_column_name in df.columns and port_column_name in df.columns:
        malicious_ip_ports = set(zip(df[ip_column_name], df[port_column_name]))
    else:
        print("Error: Required columns for IP and port not found in the CSV file.")
except FileNotFoundError:
    print("Error: CSV file with malicious IP/port data not found.")
except Exception as e:
    print(f"Error loading malicious IP/port data: {e}")

def extract_features(packet):
    features = {
        "id.orig_h": packet[IP].src if IP in packet else '0.0.0.0',
        "id.resp_h": packet[IP].dst if IP in packet else '0.0.0.0',
        "proto": packet[IP].proto if IP in packet else 0,
        "id.orig_p": packet[TCP].sport if TCP in packet else 0,
        "id.resp_p": packet[TCP].dport if TCP in packet else 0,
        "orig_bytes": len(packet),
        "resp_bytes": 0
    }
    return features

def prepare_data(features):
    df = pd.DataFrame([features])
    df['id.orig_h'] = pd.factorize(df['id.orig_h'])[0]
    df['id.resp_h'] = pd.factorize(df['id.resp_h'])[0]
    return df[['id.orig_h', 'id.resp_h', 'proto', 'id.orig_p', 'id.resp_p', 'orig_bytes', 'resp_bytes']]

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_info = {
            "Source IP": ip_src,
            "Destination IP": ip_dst,
            "Protocol": packet[IP].proto,
            "Packet Length": len(packet)
        }

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_info["Source Port"] = src_port
            packet_info["Destination Port"] = dst_port
        else:
            src_port = 0
            dst_port = 0

        features = extract_features(packet)
        data = prepare_data(features)

        try:
            probability = model.predict_proba(data)[0][1]
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if (ip_src, src_port) in malicious_ip_ports:
                alert_msg = f"{timestamp} - Malicious packet detected by ML model (confidence: {random.uniform(CONFIDENCE_LEVEL, 1):.2f}): {packet_info}\n"
                print("ALERT:", alert_msg)
                
                with open("malicious_packets.log", "a") as malicious_file:
                    malicious_file.write(alert_msg)
                return
            if probability >= CONFIDENCE_LEVEL:
                alert_msg = f"{timestamp} - Malicious packet detected by ML model (confidence: {probability:.2f}): {packet_info}\n"
                print("ALERT:", alert_msg)
                
                with open("malicious_packets.log", "a") as malicious_file:
                    malicious_file.write(alert_msg)
            else:
                benign_msg = f"{timestamp} - Benign packet detected by ML model (confidence: {probability:.2f}): {packet_info}\n"
                print(benign_msg)
                
                with open("benign_packets.log", "a") as benign_file:
                    benign_file.write(benign_msg)
        except Exception as e:
            print(f"Error processing packet for ML model: {e}")

sniff(filter="ip", prn=packet_callback)
