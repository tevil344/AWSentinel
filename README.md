# AWSentinel

> BloodHound-style AWS Attack Path Analysis & Autonomous Remediation Platform

AWSentinel is an open-source AWS security analysis platform designed to detect, explain, and eventually remediate security weaknesses that can lead to:

- AWS account compromise
- Privilege escalation
- Lateral movement
- Unauthorized administrative access
- Exposure of sensitive cloud resources

The project focuses on identifying the **root causes** behind cloud compromise instead of only generating compliance reports.

---

# Why AWSentinel Exists

Most AWS environments gradually accumulate:

- Excessive IAM permissions
- Overly permissive trust relationships
- Publicly exposed resources
- Misconfigured security groups
- Unused but dangerous access paths

Over time, these create hidden privilege escalation chains and lateral movement opportunities that attackers can exploit after compromising even a low-privileged identity.

Existing tools often stop at:
- Detection
- Compliance checks
- Static reporting

AWSentinel aims to go further by:
1. Discovering attack paths
2. Explaining how they work
3. Visualizing compromise relationships
4. Safely recommending and eventually applying remediations

---

# Core Features

## Privilege Escalation Path Detection

Detect known AWS privilege escalation techniques including:

- `iam:PassRole + ec2:RunInstances`
- `iam:AttachUserPolicy`
- `iam:PutUserPolicy`
- `iam:CreatePolicyVersion`
- `sts:AssumeRole`
- `iam:AddUserToGroup`

and many more.

---

## Lateral Movement Graph Analysis

Builds a graph of relationships between:

- IAM Users
- IAM Roles
- IAM Groups
- Trust Policies
- Service-linked identities
- Resource access paths

This enables analysis such as:

> If Principal A is compromised, what other principals or services can also be compromised?

The graphing model is inspired by tools like BloodHound and PMapper.

---

## Resource Exposure Detection

Detects dangerous cloud exposures including:

- Public S3 buckets
- Wildcard bucket policies
- Insecure security groups
- Open SSH/RDP access
- Excessive IAM permissions
- Broad trust relationships

---

## AI Explanation Layer (Planned)

Future versions will include an AI-powered reasoning engine capable of:

- Explaining attack paths in plain English
- Describing attacker workflows
- Explaining abused permissions and services
- Recommending remediation procedures

---

## Autonomous Remediation Engine (Planned)

Later versions aim to safely remediate issues using:

- Sandbox validation
- Blast-radius analysis
- Rollback support
- Operator approval workflows
- Safety scoring

---

# Core Challenges

## 1. Credential Security & Trust

AWSentinel requires AWS access in order to analyze cloud environments. Because of this, credential handling is treated as a primary security concern.

### Security Goals

- Prefer temporary STS credentials over long-lived access keys
- Avoid storing credentials permanently on disk
- Separate scan roles from remediation roles
- Support local/offline execution modes
- Scrub sensitive account information before external AI usage
- Follow least-privilege access principles

The goal is to ensure AWSentinel itself does not become an additional attack surface while analyzing AWS accounts.

---

## 2. Safe Remediation Without Breaking Production Workloads

Blindly removing permissions or modifying policies can unintentionally break production applications, infrastructure automation, scheduled workflows, or legacy integrations.

AWSentinel follows a conservative remediation philosophy:

- Detection before automation
- Validation before remediation
- Sandbox simulation where possible
- Operator approval for high-risk actions
- Rollback support
- Workload continuity prioritized over aggressive permission removal

The objective is not simply to remove permissions, but to securely reduce attack surface while preserving operational stability.

---

# Project Roadmap

## v1 — Detection & Attack Path Analysis

Current foundational version focused on:

- IAM analysis
- Privilege escalation path discovery
- Lateral movement graphing
- Resource exposure scanning
- Severity scoring
- Terminal-based output

### v1 Goals

- Discover all possible privilege escalation paths
- Build AWS relationship graphs similar to BloodHound
- Detect high-risk misconfigurations
- Visualize compromise chains
- Provide actionable security findings

---

## v2 — AI Security Reasoning Layer

Planned features:

- AI-generated attack explanations
- Service-level reasoning
- Plain-English remediation guidance
- Interactive dashboard UI
- Attack chain visualization

### v2 Goals

- Explain how attacks work
- Explain why permissions are dangerous
- Help developers understand AWS attack surfaces
- Make cloud security findings easier to understand

---

## v3 — Autonomous Remediation Engine

Planned features:

- Approved remediation workflows
- Sandbox validation
- Rollback support
- Impact analysis
- Safe permission reduction
- Blast-radius scoring

### v3 Goals

- Safely eliminate root causes of compromise
- Validate remediations before deployment
- Minimize operational impact
- Support secure autonomous remediation workflows

---

# Planned Architecture

```text
awsentinel/
├── cli/
├── crawler/
├── analyser/
├── ai/
├── remediation/
├── api/
├── dashboard/
├── db/
└── tests/
```

---

# Tech Stack

| Layer | Technology |
|---|---|
| AWS SDK | boto3 / aioboto3 |
| Backend | FastAPI |
| Graph Engine | NetworkX |
| Database | SQLite |
| Frontend | React + Tailwind |
| Graph Visualization | D3.js / React Flow |
| AI Layer | Anthropic / Ollama |
| Testing | pytest + moto |

---

# Example Vision

```bash
awsentinel scan --profile default
```

Output:

- Privilege escalation findings
- Lateral movement graph
- Public exposure findings
- Severity-ranked risks
- AI-generated explanations (future)
- Safe remediation suggestions (future)

---

# Long-Term Vision

AWSentinel aims to become a:

> BloodHound-style attack path analysis platform for AWS combined with AI-powered security reasoning and safe autonomous remediation.

The goal is not only to detect security issues, but to:

- Understand them
- Explain them
- Visualize them
- Safely eliminate the root causes behind AWS account compromise

---

# Current Status

🚧 Active Development — v1 Architecture & Core Detection Engine

---

# Contributing

Contributions, ideas, security research, and privilege escalation path improvements are welcome.

Future contribution areas:

- Additional AWS service crawlers
- New privilege escalation techniques
- Graph optimizations
- Detection logic
- UI improvements
- AI prompt engineering
- Safe remediation research

---

# Disclaimer

AWSentinel is a security research and defensive tooling project.

Autonomous remediation features should be tested carefully before use in production environments. Always review generated findings and remediation plans before execution.

---

# Author

Prathmesh Mulay (Allen)

GitHub: https://github.com/tevil344
```
