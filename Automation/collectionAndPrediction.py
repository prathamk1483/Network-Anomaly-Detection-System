import pandas as pd
from scapy.all import rdpcap
import joblib
import warnings
warnings.filterwarnings('ignore')

# Read the pcap file
packets = rdpcap('capture.pcap')

# Initialize lists to store features
flow_data = []

# Process each packet
for packet in packets:
    if 'IP' in packet:
        flow_data.append({
            'src_ip': packet['IP'].src,
            'dst_ip': packet['IP'].dst,
            'src_port': packet['IP'].sport if 'TCP' in packet or 'UDP' in packet else 0,
            'dst_port': packet['IP'].dport if 'TCP' in packet or 'UDP' in packet else 0,
            'packet_length': len(packet),
            'timestamp': packet.time,
            'direction': 'forward' if packet['IP'].src < packet['IP'].dst else 'backward'
        })

# Convert to DataFrame
df = pd.DataFrame(flow_data)

# Calculate flow-based features'
try:
    df['flow_id'] = df['src_ip'] + '-' + df['dst_ip'] + '-' + df['src_port'].astype(str) + '-' + df['dst_port'].astype(str)
except:
    exit()

# Separate forward and backward packets
forward_df = df[df['direction'] == 'forward']
backward_df = df[df['direction'] == 'backward']

# Calculate forward packet statistics
forward_stats = forward_df.groupby('flow_id').agg({
    'packet_length': ['std', 'mean', 'min', 'max', 'sum'],
    'timestamp': ['min', 'max']
}).reset_index()
forward_stats.columns = [
    'flow_id',
    'fwd_packet_length_std', 'fwd_packet_length_mean', 'fwd_packet_length_min', 'fwd_packet_length_max', 'total_length_fwd_packets',
    'flow_start_time', 'flow_end_time'
]

# Calculate backward packet statistics
backward_stats = backward_df.groupby('flow_id').agg({
    'packet_length': ['std', 'mean', 'min', 'max', 'sum'],
    'timestamp': ['min', 'max']
}).reset_index()
backward_stats.columns = [
    'flow_id',
    'bwd_packet_length_std', 'bwd_packet_length_mean', 'bwd_packet_length_min', 'bwd_packet_length_max', 'total_length_bwd_packets',
    'bwd_flow_start_time', 'bwd_flow_end_time'
]

# Merge forward and backward stats
flow_stats = pd.merge(forward_stats, backward_stats, on='flow_id', how='outer')

# Calculate additional features
flow_stats['flow_duration'] = flow_stats['flow_end_time'] - flow_stats['flow_start_time']
flow_stats['flow_bytes/s'] = (flow_stats['total_length_fwd_packets'] + flow_stats['total_length_bwd_packets']) / (flow_stats['flow_duration'] + 1)
flow_stats['flow_packets/s'] = (forward_df.groupby('flow_id').size() + backward_df.groupby('flow_id').size()) / (flow_stats['flow_duration'] + 1)

# Calculate inter-arrival time (IAT) features
df['prev_timestamp'] = df.groupby('flow_id')['timestamp'].shift(1)
df['iat'] = df['timestamp'] - df['prev_timestamp']

# Aggregate IAT features
iat_stats = df.groupby('flow_id')['iat'].agg(['std', 'min', 'max', 'mean']).reset_index()
iat_stats.columns = ['flow_id', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max', 'flow_iat_mean']

# Merge IAT stats with flow_stats
flow_stats = pd.merge(flow_stats, iat_stats, on='flow_id', how='left')

# Fill all NaN values with appropriate defaults
flow_stats = flow_stats.fillna({
    'fwd_packet_length_std': 0,
    'fwd_packet_length_mean': 0,
    'fwd_packet_length_min': 0,
    'fwd_packet_length_max': 0,
    'total_length_fwd_packets': 0,
    'bwd_packet_length_std': 0,
    'bwd_packet_length_mean': 0,
    'bwd_packet_length_min': 0,
    'bwd_packet_length_max': 0,
    'total_length_bwd_packets': 0,
    'bwd_flow_start_time': flow_stats['flow_start_time'],  # Use flow_start_time as default
    'bwd_flow_end_time': flow_stats['flow_end_time'],    # Use flow_end_time as default
    'flow_duration': 0,
    'flow_bytes/s': 0,
    'flow_packets/s': 0,
    'flow_iat_std': 0,
    'flow_iat_min': 0,
    'flow_iat_max': 0,
    'flow_iat_mean': 0
})

# Ensure no empty values remain

feature_list = [
    "bwd_packet_length_std", "flow_iat_min", "fwd_packet_length_std", 
    "flow_iat_std", "total_length_bwd_packets", "flow_bytes/s", 
    "bwd_packet_length_max", "total_length_fwd_packets", "flow_duration", 
    "flow_iat_mean", "fwd_iat_total", "fwd_packet_length_min"
]
encodings = ['BENIGN' ,'Bot' ,'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
 'DoS slowloris' ,'FTP-Patator', 'Heartbleed' ,'Infiltration' ,'PortScan',
 'SSH-Patator' ,'Web Attack - Brute Force', 'Web Attack - Sql Injection',
 'Web Attack - XSS']

model = joblib.load('../EDA/LatestModels/Random_Forest.joblib')

for i in range(len(flow_stats)):  # ✅ Fixed iteration issue
    row = {feature: flow_stats.iloc[i][feature] if feature in flow_stats.columns else 0 for feature in feature_list}
    
    # Convert to DataFrame
    row_df = pd.DataFrame([row])

    # Make prediction
    prediction = model.predict(row_df)

    # Print the corresponding label
    print(f"Row {i} Prediction: {encodings[prediction[0]]}")