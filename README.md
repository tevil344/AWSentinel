# AWSentinel

AWSentinel is an open-source AWS security analysis platform that crawls AWS accounts and later performs privilege escalation analysis, lateral movement detection, attack-path graphing, and autonomous remediation.

## Phase 1: Core Async IAM Crawler & Skeleton
Provides CLI to scan AWS account credentials and store raw JSON IAM resources in an SQLite database.
