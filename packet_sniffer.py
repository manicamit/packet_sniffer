import scapy
from scapy.all import sniff
import csv
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import threading
from threading import Timer

# Dictionary to store packet types and their counts over time
packet_type_counts = defaultdict(int)
timestamps = []
packet_summary_data = []

# CSV export function
def export_to_csv(filename, data):
    try:
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Time", "Packet Summary"])
            writer.writerows(data)
        print(f"Packet data successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving CSV file: {e}")
        
# Function to print protocol counts
def print_protocol_counts():
    print("\nProtocol Counts:")
    for protocol, count in packet_type_counts.items():
        print(f"{protocol}: {count}")


# Packet handler function
def packet_handler(packet):
    summary = packet.summary()                                                    # .summary() provides concise summary of packet details
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    
    # Print packet summary to console
    print(f"{timestamp} - {summary}")                                            # adds time stamp to summary
    
    # Append data for CSV export
    packet_summary_data.append([timestamp, summary])
    
    # Determine the protocol type
    if packet.haslayer('IP'):
        protocol = packet['IP'].proto
        if protocol == 1:
            protocol = 'ICMP'
        elif protocol == 6:
            protocol = 'TCP'
        elif protocol == 17:
            protocol = 'UDP'
        else:
            protocol = 'IP'
    elif packet.haslayer('ARP'):
        protocol = 'ARP'
    else:
        protocol = 'Other'
    
    packet_type_counts[protocol] += 1
    
    # Append timestamp for plotting
    timestamps.append(timestamp)

# Function to stop sniffing after a timeout
def stop_sniffing():
    global sniffing
    sniffing = False
    print("Stopping sniffing due to timeout.")

# Start sniffing packets
def start_sniffing(interface, csv_filename):
    global sniffing
    sniffing = True
    print("Sniffing started...")

    # Start the Timer to stop sniffing after 10 seconds, customize according to your needs
    timer = Timer(10, stop_sniffing)
    timer.start()

    try:
        sniff(iface=interface, prn=packet_handler, store=False, timeout=10)   
        #set store=true if you want to capture packets in memory and store it for later analysis, but takes too much RAM for large captures
    except KeyboardInterrupt:
        print("Sniffing stopped.")

    # Cancel the timer if sniffing is stopped early, whether manually by keyboard interrupt or by system
    timer.cancel()

    # Export packet data to CSV
    export_to_csv(csv_filename, packet_summary_data)
    
    # Plot the graph
    plot_packet_data()
    
    # Print protocol counts
    print_protocol_counts()

# Plotting packet data over time
def plot_packet_data():
    plt.figure(figsize=(10, 6))
    
    # Plot packet counts for each protocol
    for protocol, count in packet_type_counts.items():
        plt.bar(protocol, count)
    
    plt.title("Packet Type Count")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    
    # Save plot to a file instead of displaying it
    plt.savefig("packet_type_count.png")
    print("Plot saved as packet_type_count.png")
    plt.close()  # Close the plot to free up resources

# Main execution
interface = input("Enter the interface to sniff (e.g., eth0): ")
csv_filename = input("Enter the CSV filename to save packet data (e.g., packets.csv): ")
start_sniffing(interface, csv_filename)

