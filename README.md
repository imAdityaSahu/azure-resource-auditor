# Azure Resource Auditor

A Python-based security auditing tool for Microsoft Azure subscriptions. Built to identify misconfigurations, orphaned resources, and privilege escalation risks across an Azure environment.

## What it does

- Scans all Resource Groups and flags empty/orphaned ones
- Audits RBAC Role Assignments and detects overprivileged accounts
- Pulls Security Center recommendations and flags unhealthy resources
- Generates a clean HTML security report automatically

## Tech Stack

- Python 3
- Azure SDK (azure-mgmt-resource, azure-mgmt-authorization, azure-mgmt-security)
- Azure CLI Authentication
- python-dotenv

## Setup & Usage

1. Clone the repo
   git clone https://github.com/YOUR_USERNAME/azure-resource-auditor.git
   cd azure-resource-auditor

2. Install dependencies
   pip install -r requirements.txt

3. Login to Azure CLI
   az login

4. Create a .env file
   AZURE_SUBSCRIPTION_ID=your-subscription-id-here

5. Run the auditor
   python3 auditor.py

## Output

The tool outputs results in the terminal and generates a report.html file with a full visual security report.

## Author

Aditya Sahu — Cloud Security Enthusiast