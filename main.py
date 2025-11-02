import sqlite3
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from scapy.all import rdpcap  # Для парсингу pcap (встанови scapy якщо потрібно, але для demo - синтетика)

# Ініціалізація БД (з твого проєкту)
def init_db():
    conn = sqlite3.connect('logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (timestamp TEXT, source_ip TEXT, dest_ip TEXT, protocol TEXT, packet_size INTEGER)''')
    conn.commit()
    return conn

# Парсинг pcap і вставка в БД (приклад з синтетичними даними; для реальних - rdpcap('file.pcap'))
def load_data(conn):
    # Синтетичні дані для demo
    data = [
        ('2025-11-02 10:00:00', '192.168.1.1', '8.8.8.8', 'TCP', 100),
        ('2025-11-02 10:01:00', '192.168.1.1', '8.8.8.8', 'TCP', 150),
        # Аномалія: великий розмір
        ('2025-11-02 10:02:00', '192.168.1.2', '8.8.8.8', 'UDP', 5000),
    ]
    c = conn.cursor()
    c.executemany("INSERT INTO logs VALUES (?, ?, ?, ?, ?)", data)
    conn.commit()

# Аналіз з ML: Виявлення аномалій
def detect_anomalies(conn):
    df = pd.read_sql_query("SELECT * FROM logs", conn)
    # Фічі: packet_size, числові timestamp (для простоти - індекс)
    features = df[['packet_size']].values  # Додай більше фіч (e.g. freq by IP)
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    dbscan = DBSCAN(eps=0.5, min_samples=2)
    clusters = dbscan.fit_predict(features_scaled)
    
    df['cluster'] = clusters
    anomalies = df[df['cluster'] == -1]  # -1 = аномалія
    
    return anomalies

# Візуалізація
def visualize(df, anomalies):
    plt.scatter(df.index, df['packet_size'], c='blue', label='Normal')
    plt.scatter(anomalies.index, anomalies['packet_size'], c='red', label='Anomaly')
    plt.xlabel('Log Index')
    plt.ylabel('Packet Size')
    plt.legend()
    plt.savefig('anomaly_plot.png')
    print("Plot saved as anomaly_plot.png")

if __name__ == "__main__":
    conn = init_db()
    load_data(conn)
    anomalies = detect_anomalies(conn)
    print("Detected Anomalies:\n", anomalies)
    visualize(pd.read_sql_query("SELECT * FROM logs", conn), anomalies)
    conn.close()
