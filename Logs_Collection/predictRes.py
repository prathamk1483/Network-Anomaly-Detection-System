import joblib
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

# Load the model
model = joblib.load('./EDA/LatestModels/Random_Forest.joblib')
print("Model Loaded")

encodings = ['BENIGN' ,'Bot' ,'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
 'DoS slowloris' ,'FTP-Patator', 'Heartbleed' ,'Infiltration' ,'PortScan',
 'SSH-Patator' ,'Web Attack - Brute Force', 'Web Attack - Sql Injection',
 'Web Attack - XSS']

# Load the data
data = pd.read_csv('./Logs_Collection/logs.csv')

# Define the feature list
feature_list = [
    "bwd_packet_length_std", "flow_iat_min", "fwd_packet_length_std", 
    "flow_iat_std", "total_length_bwd_packets", "flow_bytes/s", 
    "bwd_packet_length_max", "total_length_fwd_packets", "flow_duration", 
    "flow_iat_mean", "fwd_iat_total", "fwd_packet_length_min"
]

# Iterate through each row in the dataset
for i in range(len(data)):
    row = {feature: data.iloc[i][feature] if feature in data.columns else 0 for feature in feature_list}

    # Convert to DataFrame and reshape it
    row_df = pd.DataFrame([row])

    # Make prediction
    prediction = model.predict(row_df)
    print(encodings[prediction[0]])
