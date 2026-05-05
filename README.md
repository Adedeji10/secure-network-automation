\# Secure Network Automation Framework

\## With GitOps and Proactive Compliance Auditing



\*\*Author:\*\* Mubarak Adedeji Shittu 

\*\*Department:\*\* Cyber Security, Osun State University

\*\*Supervisor:\*\* Professor Caleb O. Akanbi



\---



\## Overview

This repository implements a secure network automation framework

that integrates GitOps principles with proactive compliance auditing.

All network configuration changes are audited by the Inspector

before deployment via Ansible to simulated network devices.



\## Repository Structure

secure-network-automation/

├── configs/               # Network device configuration files (IaC)

│   ├── routers/           # Cisco IOS router configurations

│   ├── switches/          # Layer-2 switch configurations

│   └── firewalls/         # Firewall configurations

├── playbooks/             # Ansible deployment playbooks

│   └── roles/             # Role-based playbook structure

│       ├── cisco\_ios\_router/

│       ├── cisco\_ios\_switch/

│       └── generic\_firewall/

├── inspector/             # Python-based security auditing engine

│   └── tests/             # Unit tests for Inspector module

├── rules/                 # YAML security audit rule definitions

└── .github/

└── workflows/         # GitHub Actions CI/CD pipeline

\## Framework Components

| Component | Purpose |

|---|---|

| Git Repository | Single source of truth for all configurations |

| Inspector | Python auditing engine — audits configs before deployment |

| CI/CD Pipeline | GitHub Actions — enforces audit gate automatically |

| Ansible Engine | Deploys approved configurations to network devices |



\## Security Rules

32 rules derived from CIS Benchmarks, NIST SP 800-53,

and OWASP Network Security Testing Guide across 4 severity levels:

\- \*\*Critical\*\* (8 rules) — Forbidden protocols e.g. Telnet

\- \*\*High\*\* (16 rules) — Encryption and access control

\- \*\*Medium\*\* (13 rules) — Logging and NTP

\- \*\*Low\*\* (5 rules) — Documentation standards



\## Audit Decision Logic

\- 🔴 \*\*BLOCK\*\* — Any Critical or High violation detected

\- 🟡 \*\*WARN\*\* — Medium or Low violations (advisory only)

\- 🟢 \*\*PASS\*\* — No violations detected

