Packet Sniffer using Scapy

This Python script captures network packets in real-time using the scapy library. It provides a summary of captured packets, exports the data to a CSV file, and visualizes packet distribution based on protocol type.

Features

Sniffs network packets on a specified interface.

Captures and logs packet summaries with timestamps.

Identifies protocol types (ICMP, TCP, UDP, ARP, etc.).

Stores captured packet details in a CSV file.

Generates a bar chart visualization of protocol distribution.

Stops sniffing automatically after a specified duration (default: 10 seconds).

Requirements

Ensure you have the following dependencies installed:

pip install scapy matplotlib

Usage

Run the script and provide the necessary inputs:

python packet_sniffer.py

Enter the network interface to sniff (e.g., eth0 or wlan0).

Provide the filename to save captured packet data as a CSV file (e.g., packets.csv).

Output

Console Output: Displays captured packets along with timestamps.

CSV File: Saves packet summaries and timestamps.

Bar Chart: Generates and saves a visualization (packet_type_count.png) showing protocol counts.

Functions Overview

packet_handler(packet): Processes and logs packet details.

export_to_csv(filename, data): Saves captured data to a CSV file.

plot_packet_data(): Generates a bar chart of protocol counts.

start_sniffing(interface, csv_filename): Initiates packet sniffing on the specified interface.

Notes

Ensure you have the necessary permissions to sniff network traffic (run as root if required).

Modify the sniffing timeout (10 seconds) as needed in the script.

License

This project is licensed under the MIT License.

