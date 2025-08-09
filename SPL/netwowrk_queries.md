# 🔍 SPL Detection Queries

## 🚨 Analyzing Network Activity 

**Use Case:** My SANS GICA professor told the class that the communication with the most connection, longest duration, and most bytes is more than likely the malicious activity. You will need to filter out the internal traffic with a macro (NOT_INTERNAL_IPS).

Top 10 connections 
```spl
Index=firewall AND srcip=$ip_token$
| stats count by sourceip, destinationip, destinationport, destinationcounty
| where `NOT_INTERNAL_IPS` 
| sort -count 
| head 10
```
Longest 10 Durations
```spl
Index=firewall AND srcip=$ip_token$
| stats sum(duration_of_connection) as duration by sourceip, destinationip, destinationcounty
| where `NOT_INTERNAL_IPS`
| sort -duration_connection 
| head 10
```
Most bytes Sent (Top 10)
```spl
Index=firewall AND srcip=$ip_token$
| stats sum(sent_bytes) as Bytes by sourceip, destinationip, destinationport, destinationcounty
| where `NOT_INTERNAL_IPS` 
| table sourceip, destinationip, destinationport, destinationcounty, Bytes 
| sort -Bytes
| head 10
```
