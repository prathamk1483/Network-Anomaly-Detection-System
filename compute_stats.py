import pandas as pd

# Try reading the file with ISO-8859-1 encoding (or Latin-1, which can handle arbitrary bytes)
with open("network_logs.txt", "rb") as f:
    raw_data = f.read()

# Convert binary data to text while ignoring errors
decoded_data = raw_data.decode("ISO-8859-1", errors="ignore")

# Write cleaned data back to file
with open("cleaned_network_logs.txt", "w", encoding="utf-8") as f:
    f.write(decoded_data)

# Now read the cleaned file
df = pd.read_csv("cleaned_network_logs.txt", sep="\t", header=None, names=[
    "Time", "SourceIP", "DestIP", "Protocol", "Frame_Length", 
    "TCP_Length", "UDP_Length", "Time_Delta", "Epoch_Time"
])

# Convert missing values to 0
df.fillna(0, inplace=True)

# Compute additional features
df["Total_Packet_Length"] = df["TCP_Length"] + df["UDP_Length"]
df["Flow_Bytes"] = df["Frame_Length"].cumsum()  # Approximate flow bytes

# Save processed logs
df.to_csv("processed_logs.csv", index=False)

print("✅ Processed logs saved to processed_logs.csv")
