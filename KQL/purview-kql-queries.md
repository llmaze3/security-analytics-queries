# Microsoft Purview KQL Queries

This document serves as a centralized collection of **Kusto Query Language (KQL)** queries used in **Microsoft Purview** for investigation, compliance, and security monitoring.

The queries in this file are intended to help identify, analyze, and audit data activities such as email communications, file access, and external data sharing across the organization.

# Find All Communications Sent Externally

This query identifies communications sent to recipients **outside the internal domain** within the specified date range using Microsoft Purview KQL.

## Query

```kql
(Date=2025-01-20..2025-12-26) AND (-Recipients:<InternalDomain.com>)
