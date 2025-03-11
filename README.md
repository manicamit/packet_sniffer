# 🛠 Packet Sniffer Script

A **Python-based packet sniffer** that captures live network packets, logs their details, and saves the data to a CSV file. It also generates a bar chart showing the distribution of different packet types.  

## 📌 Features

✔️ Captures live network packets  
✔️ Identifies packet types (**ICMP, TCP, UDP, ARP, etc.**)  
✔️ Logs timestamped packet summaries  
✔️ Exports packet data to a **CSV file**  
✔️ Generates a **bar chart** of protocol distribution  
✔️ **Auto-stops sniffing** after a set timeout (default: 10 seconds)  

---

## ⚙️ Prerequisites

Make sure you have the following installed:  

### 🔹 Required Software
- **Python 3.x**  

### 🔹 Required Python Libraries  
Install the necessary dependencies using:  

```sh
pip install scapy matplotlib
```


### 🔹 **Usage**
**1️⃣ Run the script:**

```sh
python packet_sniffer.py
```

**2️⃣ Enter the required inputs when prompted:**
    Network Interface (e.g., eth0, wlan0)
    CSV Filename (e.g., packets.csv)
    
---


## 📝 **Notes**

🔹 **Run as Administrator:**

    Linux/macOS: Use sudo (e.g., sudo python packet_sniffer.py)
    Windows: Won't work for Windows

🔹 **Ensure your network interface is active and has traffic for capturing packets**

🔹 **wrpcap("<file name>", capture) stores a pcap file for wireshark analysis and stuff, change the parameter store to true and get the result of sniff function to be stored in a variable, 
      eg var = sniff(...), then check if var is not null and do wrcap(filename,var). Remember to import wrcap from scapy first.**

🔹 **sniff(offline="<file name>") for offline view of pcap file (use with prn)**
