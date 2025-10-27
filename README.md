# Snort-NIDS-Implementation
Snort-based NIDS implementation project. Detects network intrusions in real-time using custom rule-sets, performs signature-based threat analysis, and provides forensic logging.

Network Intrusion Detection System (NIDS) using Snort
Project Overview
This project details the installation, configuration, and testing of a Network Intrusion Detection System (NIDS) leveraging the powerful open-source tool Snort. The main objective was to develop and deploy an operational, signature-based NIDS capable of monitoring real-time network traffic for malicious behavior within a controlled lab environment.

The successful outcome validated the practical use of Snort to implement and maintain custom rule-sets for efficient intrusion detection and alerting against emulated cyber threats, thereby strengthening network security posture.

Key Features & Achievements

Real-time Traffic Monitoring: Deployed Snort in its primary NIDS Mode to actively analyze network traffic against a comprehensive set of predefined rules.


Signature-Based Detection: Successfully implemented and tested custom rule-sets to detect specific simulated attacks, such as ICMP and SSH authentication attempts.


Logging and Forensics: Utilized the Packet Logging Mode to capture network packets to disk (PCAP format), which is critical for incident response and forensic analysis.


Environment Simulation: Established a virtual lab environment using Ubuntu 20.04 to host Snort, a Kali Linux attacker machine, and a Metasploitable2 vulnerable server, simulating a realistic attack scenario.

Configuration: Configured the snort.conf file to define the HOME_NET (192.168.18.0/24) and ensure the Snort machine's network interface was set to promiscuous mode to observe all traffic.

Installation Requirements
A clean installation of Ubuntu 20.04 is required to host Snort, along with necessary dependencies like libpcap and DAQ.

Snort Modes of Operation (Demonstrated)
Snort was observed and configured in its three fundamental modes:


Packet Sniffer Mode: Functions like tcpdump, capturing and displaying network packet headers and payloads in real-time.


Packet Logging Mode: Captures packets and saves them to disk, often in PCAP format, for later analysis.


NIDS Mode: The primary mode, actively comparing network traffic against rules to detect malicious activity and generate alerts.


Project Conclusion and Future Scope
Conclusion
The project successfully demonstrated the implementation of a robust, signature-based Network Intrusion Detection System using Snort, confirming it as a flexible and powerful tool for real-time threat analysis.

Future Scope
Recommended next steps for expansion:


SIEM Integration: Integrate Snort alerts with a Security Information and Event Management (SIEM) system (e.g., Splunk or ELK Stack) for centralized visualization and advanced correlation of threat events.


Conversion to NIPS: Upgrade the setup to a Network Intrusion Prevention System (NIPS) by enabling inline capability to actively block malicious packets, not just alert on them.


Anomaly Detection: Incorporate anomaly-based detection using machine learning models to detect zero-day threats that do not match existing signatures.

Project Report
The complete, detailed documentation of this project, including step-by-step installation and configuration instructions, is available here:

Snort report.pdf
