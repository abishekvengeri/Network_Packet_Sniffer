# 🛜 Python Network Packet Sniffer

A powerful **Python-based network packet sniffer** that captures real-time network traffic using **Scapy**.  
This tool helps analyze **TCP, UDP, ICMP, and IP traffic**, previews payloads, and saves captured packets to **PCAP files** for further analysis in **Wireshark**.  

🔍 **Monitor network traffic like a pro!**  

---

## 🔥 Features

✅ **Live Packet Capture** (TCP, UDP, ICMP, IP)  
✅ **BPF Filtering Support** (e.g., `"tcp port 80"`)  
✅ **Payload Preview** (First 80 characters of text-based data)  
✅ **PCAP Export** (Save packets for later analysis)  
✅ **Graceful CTRL+C Handling** (Stops & saves packets)  
✅ **Secure & Lightweight** (Uses only `Scapy`)  

---

## 📌 Installation

Ensure you have **Python 3.6+** and install dependencies:

```bash
pip install scapy
