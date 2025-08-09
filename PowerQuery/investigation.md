# 🔍 KQL Detection Queries

## 🚨 Login 

**Use Case:** Analyze device login activity 

```m 
endpoint.name contains ("DeviceName") 
| filter event.type == "Login"
| columns event.time, "Username"=event.login.userName, "Login Type"=event.login.type, "Failure Reason"=event.login.failureReason, "Cmdline"= src.process.cmdline, src.process.displayName, event.login.loginIsSuccessful 
| sort - event.time
| limit 100
```
Find only failed logins:

```m 
| filter( event.type == "Login" AND event.login.loginIsSuccessful == false )
```
## 🚨 Network Connections

**Use Case:** This query is useful for determining if the device connected to a suspicious domain

```m 
endpoint.name = 'DeviceName' AND event.type in ("DNS Resolved", "CONNECT","GET","POST")
| columns event.time, "Event Type"=event.type, "Username"=src.process.user, "Source Process"=src.process.image.path, "Request"=url.address OR event.dns.request 
| filter Request contains "domain[.]com"
```

**Use Case:** This query is  useful for analyzing device connections and the related process

```m 
endpoint.name contains ("DeviceName")
| filter event.type =="IP Connect"
| columns  event.time, event.type, src.process.displayName, src.process.cmdline, dst.ip.address, dst.port.number
```
