# 🔍 KQL Detection Queries

## 🚨 Email Investigation 

**Use Case:** Determine if any emails in the org have a specific link 

Join EmailEvents and EmailUrlInfo table
```kql
EmailEvents 
| join kind=leftouter EmailUrlInfo on NetworkMessageId 
| where Url contains "domain[.]com"
| distinct RecipientEmailAddress, Subject, DeliveryAction, SenderIPv4, SenderFromDomain, SenderMailFromDomain
```

**Use Case:** Determine if anyone from the org clicked a potentially malicious link in a phishing email

Join UrlClickEvents and EmailEvents table
```kql
UrlClickEvents 
| join kind=leftouter EmailEvents on NetworkMessageId 
| where SenderMailFromAddress contains "user@email" 
| distinct Timestamp, SenderMailFromAddress, RecipientEmailAddress, Subject, Url, ActionType  
```

**Use Case:** Searching for an email by the subject

```kql
EmailEvents
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
| where Subject contains "Title"
    and RecipientEmailAddress contains "user@email"
```

**Use Case:** Format For Date (Between Day & Time)

```kql
(Date=2025-11-14T14:00:00..2025-11-14T16:00:00) AND (Recipients:<email>) 
```
