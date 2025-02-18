# Set output file
$outputFile = "network_logs.txt"

# Check if TShark is installed
if (-Not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    Write-Output "Error: TShark is not installed. Install Wireshark and ensure TShark is added to PATH."
    exit
}

# Capture network packets using TShark (modify interface number if needed)
Write-Output "Capturing network packets..."
tshark -i 4 -c 100 -T fields -E separator=tab -e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e udp.length -e frame.time_delta -e frame.time_epoch | Out-File -Encoding utf8 $outputFile

Write-Output "Packet data collected! Running Python script for additional computations..."

# Check if Python is installed
if (-Not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Output "Error: Python is not installed. Install Python and ensure it is added to PATH."
    exit
}

# Run Python script to process logs
python compute_stats.py
