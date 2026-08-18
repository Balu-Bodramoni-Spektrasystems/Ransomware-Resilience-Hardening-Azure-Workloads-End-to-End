# Challenge 1: Establish resilient backup governance

### Estimated Duration: 25 minutes

## Scenario

You are the hybrid operator for a ransomware-resilience sandbox. Before hardening storage or testing recovery, you must prove that the deployed VM has a same-session backup recovery point and that the Recovery Services vault is governed by soft delete and Resource Guard-backed multi-user authorization (MUA) for selected high-impact Azure Backup operations.

## Overview

In this challenge, you will discover the lab resources deterministically, verify VM backup coverage and the single same-session recovery point, confirm vault soft delete, verify the vault-to-Resource Guard mapping, identify the protected operation boundary, and record one compact governance evidence checklist.

> [!Important]
> Resource Guard-backed MUA protects selected critical Azure Backup operations. It does not block every administrative action in the subscription, and it does not replace least-privilege RBAC, monitoring, or restore testing.

## Objectives

- Task 1: Discover the deployed resources by exact deployment context
- Task 2: Verify VM backup and the same-session recovery point
- Task 3: Verify soft delete and Resource Guard-backed MUA
- Task 4: Record one compact governance checklist and validate

## Task 1: Discover the deployed resources by exact deployment context

In this task, you will sign in and identify the lab resource group, VM, Recovery Services vault, Resource Guard, and primary storage account without relying on partial name searches.

1. Sign in to <https://portal.azure.com> using the lab credentials:
   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
2. Confirm you are using subscription <inject key="SubscriptionID"></inject> and tenant <inject key="TenantID"></inject>.
3. Open **Cloud Shell** in **Bash** mode.
4. Copy the following values for the discovery script prompts:
   - Subscription ID: <inject key="SubscriptionID"></inject>
   - Deployment identifier: **<inject key="DeploymentID" enableCopy="false"/>**
5. Run the following compact discovery script. It first resolves the exact deployment-tagged resource group, then identifies the primary lab storage account by the presence of all three canonical containers: `containera-unprotected`, `containerb-protectme`, and `lab-evidence`.

   ```bash
   read -r -p "Paste the lab Subscription ID: " SUBSCRIPTION_ID
   read -r -p "Paste the lab DeploymentID value: " DEPLOYMENT_ID
   az account set --subscription "$SUBSCRIPTION_ID"

   mapfile -t LAB_RGS < <(
     {
       az group list --tag "deploymentId=$DEPLOYMENT_ID" --query "[].name" -o tsv
       az group list --tag "DeploymentID=$DEPLOYMENT_ID" --query "[].name" -o tsv
       az resource list --tag "deploymentId=$DEPLOYMENT_ID" --query "[].resourceGroup" -o tsv
       az resource list --tag "DeploymentID=$DEPLOYMENT_ID" --query "[].resourceGroup" -o tsv
     } | sed '/^$/d' | sort -u
   )

   if [ "${#LAB_RGS[@]}" -ne 1 ]; then
     echo "ERROR: Expected exactly one deployment-tagged resource group for $DEPLOYMENT_ID; found ${#LAB_RGS[@]}."
     printf ' - %s\n' "${LAB_RGS[@]}"
     exit 1
   fi

   LAB_RG="${LAB_RGS[0]}"
   echo "LAB_RG=$LAB_RG"
   echo
   echo "Core resources:"
   az resource list --resource-group "$LAB_RG" \
     --query "[].{name:name,type:type,location:location}" -o table

   required=(containera-unprotected containerb-protectme lab-evidence)
   matches=()
   while read -r account; do
     [ -z "$account" ] && continue
     containers=$(az storage container list --account-name "$account" --auth-mode login --query "[].name" -o tsv 2>/dev/null || true)
     ok=true
     for c in "${required[@]}"; do
       printf '%s\n' "$containers" | grep -qxF "$c" || ok=false
     done
     [ "$ok" = true ] && matches+=("$account")
   done < <(az storage account list --resource-group "$LAB_RG" --query "[].name" -o tsv)

   if [ "${#matches[@]}" -ne 1 ]; then
     echo "ERROR: Expected exactly one primary storage account with the three canonical containers; found ${#matches[@]}."
     printf ' - %s\n' "${matches[@]}"
     exit 1
   fi

   echo
   echo "PRIMARY_STORAGE=${matches[0]}"
   echo "Canonical containers: ${required[*]}"
   ```

6. Continue only if the script reports exactly one `LAB_RG` and one `PRIMARY_STORAGE` account.
7. From the **Core resources** table, note the names of these resources for the checklist in Task 4:
   - The Azure VM used as the operator workstation and recovery target.
   - The Recovery Services vault.
   - The Resource Guard.
   - The primary storage account reported by the script.

## Task 2: Verify VM backup and the same-session recovery point

In this task, you will verify that Azure Backup is protecting the VM and that the lab has a recovery point created during this session.

1. In the Azure portal, open the `LAB_RG` resource group discovered in Task 1.
2. Open the **Recovery Services vault**.
3. Go to **Backup items** and open the Azure VM backup item for the operator VM.
4. Confirm the VM appears as protected by the vault. Record the protected VM name and backup policy name shown in the backup item details.
5. Open the VM backup item's recovery point or backup job view.
6. Confirm there is one current-session recovery point or a completed same-session backup job. Record the most recent recovery point time or completed job time.
7. If a backup job is still running, do not stop protection or change the policy. Record the job as `InProgress` and continue; later restore work depends on allowing the job to finish.

> [!Note]
> This lab intentionally creates only one VM recovery point in the same lab session. You are not expected to find a multi-day recovery history.

## Task 3: Verify soft delete and Resource Guard-backed MUA

In this task, you will verify the vault-level anti-tampering controls without performing a destructive operation.

1. In the Recovery Services vault, open the vault **Properties** or security settings that show **Soft delete**.
2. Confirm soft delete is enabled, always-on, or enforced by the platform. Record the state and retention value if Azure displays one.
3. Do not disable soft delete, stop backup, delete backup data, or modify backup policy retention.
4. Open the **Resource Guard** discovered in Task 1.
5. On the Resource Guard **Overview** page, record the Resource Guard name and resource ID.
6. Open the Resource Guard **Properties** page and review the **Recovery Services vault** protected operations.
7. Record at least the mandatory protected operations shown by Azure Backup:
   - Disable soft delete or security features.
   - Remove MUA protection.
8. Also record any optional protected operations that are enabled, such as delete protection, modify protection, modify policy, stop backup and retain data, modify encryption settings, disable immutability, restore, or hybrid-container deletion.
9. Return to the Recovery Services vault and open **Properties** > **Multi-User Authorization**.
10. Verify that the vault is protected with the deployed Resource Guard. Record whether the mapping was already present from bootstrap or whether the portal shows it as enabled through the Resource Guard you inspected.
11. Verify the learner identity's intended Resource Guard posture as far as the portal allows: the learner may be able to read the guard for verification, but should not have standing **Contributor**, **Backup MUA Admin**, or **Backup MUA Operator** authority on the Resource Guard.

> [!Important]
> Do not attempt to remove MUA, disable soft delete, stop protection, reduce retention, or delete backup data in this challenge. Challenge 3 covers an attributable protected-path denial safely.

## Task 4: Record one compact governance checklist and validate

In this task, you will create one concise evidence record instead of separate narrative writeups for each setting.

1. Create a Challenge 1 evidence entry using the checklist below. Keep each field short.

   | Evidence field | Value to record |
   | --- | --- |
   | Deployment identifier | **<inject key="DeploymentID" enableCopy="false"/>** |
   | Resource group | `LAB_RG` from Task 1 |
   | Primary storage account | `PRIMARY_STORAGE` from Task 1 |
   | VM protected by vault | VM name from Backup items |
   | Recovery Services vault | Vault name |
   | Backup policy | Policy name shown for the VM backup item |
   | Same-session recovery point or job | Recovery point timestamp, completed backup job time, or `InProgress` job status |
   | Soft delete | Enabled, always-on, or enforced; include retention if shown |
   | Resource Guard | Resource Guard name and resource ID |
   | Vault MUA mapping | Enabled through the deployed Resource Guard |
   | Protected operations | Mandatory operations plus any enabled optional operations observed |
   | Learner Resource Guard posture | Reader/discovery only if visible; no standing Contributor, Backup MUA Admin, or Backup MUA Operator authority observed |

2. Add this one-sentence MUA scope statement below the checklist:

   Resource Guard-backed MUA adds separate authorization for selected destructive or high-impact Azure Backup operations on the vault, such as disabling soft delete or removing MUA protection, but it does not block unrelated administration or actions performed directly against the protected VM or storage workload.

3. Run the validation after the checklist is complete.

<validation step="Backup governance configured"/>

## Summary

You discovered the lab resources deterministically, verified that the operator VM is protected by Azure Backup, confirmed the same-session recovery point or in-progress same-session backup job, checked vault soft delete, verified the vault-to-Resource Guard mapping, identified gated Azure Backup operations, and captured one compact governance record with an accurate MUA scope statement.