from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.network import NetworkManagementClient


from dotenv import load_dotenv
import os


def generate_html_report(resource_groups, roles, role_names, recommendations, nsg_data):
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Azure Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0f0f0f; color: #e0e0e0; padding: 40px; }}
        h1 {{ color: #00bfff; }}
        h2 {{ color: #00bfff; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        .card {{ background: #1a1a1a; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .warn {{ color: #ffaa00; }}
        .good {{ color: #00ff99; }}
        .risk {{ color: #ff4444; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #222; padding: 10px; text-align: left; color: #00bfff; }}
        td {{ padding: 10px; border-bottom: 1px solid #2a2a2a; }}
    </style>
</head>
<body>
    <h1>Azure Resource Auditor — Security Report</h1>
    <p>Subscription: <strong>{subscription_id}</strong></p>

    <h2>Resource Groups</h2>
    <div class="card">
        <table>
            <tr><th>Name</th><th>Location</th><th>Status</th><th>Flag</th></tr>
            {"".join([f"<tr><td>{rg.name}</td><td>{rg.location}</td><td>{rg.properties.provisioning_state}</td><td class='warn'>⚠️ Empty</td></tr>" if rg.name in resource_groups['empty'] else f"<tr><td>{rg.name}</td><td>{rg.location}</td><td>{rg.properties.provisioning_state}</td><td class='good'>✅ OK</td></tr>" for rg in resource_groups['all']])}
        </table>
    </div>

    <h2>RBAC Role Assignments</h2>
    <div class="card">
        <table>
            <tr><th>Principal ID</th><th>Role</th><th>Scope</th></tr>
            {"".join([f"<tr><td>{r.principal_id}</td><td>{role_names.get(r.role_definition_id, 'Unknown')}</td><td>{r.scope}</td></tr>" for r in roles])}
        </table>
    </div>

    <h2>Security Center</h2>
    <div class="card">
        {"<p class='good'>No security recommendations found.</p>" if not recommendations else "".join([f"<p class='risk'>⚠️ {rec.display_name} — Unhealthy: {rec.unhealthy_resource_count}</p>" for rec in recommendations])}
    </div>

    <h2>Network Security Groups</h2>
    <div class="card">
        <table>
            <tr><th>Name</th><th>Resource Group</th><th>Location</th><th>Status</th></tr>
            {"".join([
                f"<tr><td>{n['name']}</td><td>{n['resource_group']}</td><td>{n['location']}</td><td class='risk'>🚨 Risk Detected</td></tr>"
                if n['risk_found'] else
                f"<tr><td>{n['name']}</td><td>{n['resource_group']}</td><td>{n['location']}</td><td class='good'>✅ Clean</td></tr>"
                for n in nsg_data
            ])}
        </table>
    </div>

</body>
</html>
"""
    with open("report.html", "w") as f:
        f.write(html)
    print("\n  Report saved as report.html — open it in your browser!")


# Auth
load_dotenv()
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
credential = AzureCliCredential()
resource_client = ResourceManagementClient(credential, subscription_id)

print("\n" + "="*50)
print("   AZURE RESOURCE AUDITOR")
print("="*50)

# Resource Groups
print("\n[+] Scanning Resource Groups & Resources...\n")

resource_groups = {'all': [], 'empty': []}

for rg in resource_client.resource_groups.list():
    resource_groups['all'].append(rg)

    print(f"\n📁 Resource Group : {rg.name}")
    print(f"   Location       : {rg.location}")
    print(f"   Status         : {rg.properties.provisioning_state}")
    print("-" * 40)

    resources = list(resource_client.resources.list_by_resource_group(rg.name))

    if not resources:
        resource_groups['empty'].append(rg.name)
        print("   ⚠️  WARNING: Empty resource group")
    else:
        print(f"   Resources found: {len(resources)}")
        for res in resources:
            print(f"      → {res.type.split('/')[-1]}: {res.name}")

# RBAC
print("\n" + "="*50)
print("\n[+] Scanning Role Assignments (RBAC)...\n")

auth_client = AuthorizationManagementClient(credential, subscription_id)
roles = list(auth_client.role_assignments.list_for_subscription())

owner_count = 0
role_names = {}

for role in roles:
    role_def_id = role.role_definition_id
    role_def = auth_client.role_definitions.get_by_id(role_def_id)
    role_name = role_def.role_name
    role_names[role_def_id] = role_name

    if role_name == "Owner":
        owner_count += 1

    print(f"  Principal ID : {role.principal_id}")
    print(f"  Role Name    : {role_name}")
    print(f"  Scope        : {role.scope}")
    print("-" * 40)

if owner_count > 1:
    print(f"\n  🚨 RISK: {owner_count} Owners found — too many privileged users!")
else:
    print(f"\n  ✅ RBAC looks clean — only {owner_count} Owner found.")

print(f"  Total Role Assignments: {len(roles)}")

# Security Center
print("\n" + "="*50)
print("\n[+] Scanning Security Center Recommendations...\n")

security_client = SecurityCenter(credential, subscription_id)
recommendations = list(security_client.secure_score_controls.list())

if not recommendations:
    print("  ✅ No security recommendations found.")
else:
    for rec in recommendations:
        print(f"  Control     : {rec.display_name}")
        print(f"  Score       : {rec.score.current} / {rec.score.max}")
        print(f"  Unhealthy   : {rec.unhealthy_resource_count} resources")
        if rec.unhealthy_resource_count > 0:
            print(f"  ⚠️  ACTION NEEDED")
        print("-" * 40)



# NSG management
network_client = NetworkManagementClient(credential, subscription_id)

print("\n" + "="*50)
print("\n[+] Scanning Network Security Groups...\n")

nsgs = list(network_client.network_security_groups.list_all())

nsg_data = []

for nsg in nsgs:
    risk_found = False
    print(f"  NSG            : {nsg.name}")
    print(f"  Resource Group : {nsg.id.split('/')[4]}")
    print(f"  Location       : {nsg.location}")
    print("-" * 40)
    for rule in nsg.security_rules:
        if rule.direction == "Inbound" and rule.access == "Allow":
            if rule.destination_port_range in ["22", "3389", "*"] and \
               rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
                print(f"  🚨 RISK: Port {rule.destination_port_range} open to internet — Rule: {rule.name}")
                risk_found = True
    if not risk_found:
        print("  ✅ No risky rules found")
    nsg_data.append({
        "name": nsg.name,
        "resource_group": nsg.id.split('/')[4],
        "location": nsg.location,
        "risk_found": risk_found,
    })

    
    


# Generate Report
generate_html_report(resource_groups, roles, role_names, recommendations, nsg_data)

print("\n" + "=" * 50)
print("   SCAN COMPLETE")
print("=" * 50)