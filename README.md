# Azure Resource Auditor

I built this security auditing tool in Python specifically for Microsoft Azure subscriptions. It's designed to help you catch those pesky misconfigurations, find resources that have been left behind (we've all been there!), and spot any privilege escalation risks lurking in your Azure environment.

## Here’s what it does:

- It scans all Resource Groups and highlights any that are empty or orphaned.
- It audits RBAC Role Assignments to identify accounts that have too many privileges.
- It pulls recommendations from the Security Center and flags any unhealthy resources.
- It automatically generates a neat HTML security report.

## Tech Stack

- Python 3
- Azure SDK (azure-mgmt-resource, azure-mgmt-authorization, azure-mgmt-security)
- Azure CLI Authentication
- python-dotenv

## Setup & Usage

1. Clone the repo
   - git clone https://github.com/imAdityaSahu/azure-resource-auditor.git
   - `cd azure-resource-auditor`

2. Install dependencies
   - `pip install -r requirements.txt`

3. Login to Azure CLI
   - `az login`

4. Create a `.env` file
   - AZURE_SUBSCRIPTION_ID=your-subscription-id-here

5. Run the auditor
   - `python3 auditor.py`

## Output

The tool displays results right in the terminal and creates a `report.html` file that contains a complete visual security report.

---

## Author

👤 **Aditya Sahu** — Cloud Security Enthusiast

[LinkedIn](https://www.linkedin.com/in/imadityasahu/)
