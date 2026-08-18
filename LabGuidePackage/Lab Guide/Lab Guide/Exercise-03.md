# Challenge 3: Prove the authorization boundary holds

### Estimated Duration: 20 minutes

## Scenario

You have one supplied Microsoft Entra learner identity. Your goal is to prove that the Recovery Services vault administrator cannot perform a selected Resource Guard-protected Azure Backup operation unless separate Resource Guard authority is granted through the MUA approval path.

## Overview

In this challenge, you will deterministically discover the lab resource group and evidence storage account, verify the vault-to-Resource Guard mapping, identify one protected operation, check your effective access at Resource Guard scope, observe an attributable denial, cancel safely, and upload one compact JSON evidence file to `lab-evidence/challenge-03/authorization-boundary.json`.

## Objectives

- Task 1: Discover the lab resource group and canonical storage account
- Task 2: Verify the vault-to-Resource Guard mapping and choose one protected operation
- Task 3: Check effective access and capture the denial
- Task 4: Upload authorization-boundary JSON evidence

## Task 1: Discover the lab resource group and canonical storage account

In this task, you will sign in with the supplied learner identity and resolve the exact lab resources without name guessing.

1. Sign in to <https://portal.azure.com> using the lab credentials:
   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
2. Confirm you are working in subscription <inject key="SubscriptionID"></inject> and tenant <inject key="TenantID"></inject>.
3. Open Azure Cloud Shell in Bash mode.
4. Copy these two values for the prompts in the next command:
   - Subscription ID: <inject key="SubscriptionID"></inject>
   - Deployment identifier: **<inject key="DeploymentID" enableCopy="false"/>**
5. Run the following discovery script. It requires exactly one resource group with the exact deployment tag and exactly one non-staging storage account that contains `containera-unprotected`, `containerb-protectme`, and `lab-evidence`.

   ```bash
   read -r -p "Paste the lab Subscription ID: " SUBSCRIPTION_ID
   read -r -p "Paste the lab DeploymentID value: " DEPLOYMENT_ID
   read -r -p "Paste the restore staging storage account name from the lab guide: " RESTORE_STAGING_ACCOUNT

   az account set --subscription "$SUBSCRIPTION_ID"

   mapfile -t candidate_rgs < <(
     {
       az group list --tag "deploymentId=$DEPLOYMENT_ID" --query "[].name" -o tsv
       az group list --tag "DeploymentID=$DEPLOYMENT_ID" --query "[].name" -o tsv
       az resource list --tag "deploymentId=$DEPLOYMENT_ID" --query "[].resourceGroup" -o tsv
       az resource list --tag "DeploymentID=$DEPLOYMENT_ID" --query "[].resourceGroup" -o tsv
     } | sed '/^$/d' | sort -u
   )

   if [ "${#candidate_rgs[@]}" -ne 1 ]; then
     echo "ERROR: Expected exactly one lab resource group for deployment '$DEPLOYMENT_ID'. Found ${#candidate_rgs[@]}:"
     printf ' - %s\n' "${candidate_rgs[@]}"
     exit 1
   fi

   LAB_RG="${candidate_rgs[0]}"
   echo "LAB_RG=$LAB_RG"

   mapfile -t all_storage_accounts < <(
     az storage account list --resource-group "$LAB_RG" --query "[].name" -o tsv | sed '/^$/d' | sort -u
   )

   matching_accounts=()
   for account_name in "${all_storage_accounts[@]}"; do
     if [ "$account_name" = "$RESTORE_STAGING_ACCOUNT" ]; then
       echo "Skipping restore staging account: $account_name"
       continue
     fi

     containers=$(az storage container list --account-name "$account_name" --auth-mode login --query "[].name" -o tsv 2>/tmp/container-list-error.txt || true)
     if printf '%s\n' "$containers" | grep -Fxq "containera-unprotected" && \
        printf '%s\n' "$containers" | grep -Fxq "containerb-protectme" && \
        printf '%s\n' "$containers" | grep -Fxq "lab-evidence"; then
       matching_accounts+=("$account_name")
     fi
   done

   mapfile -t matching_accounts < <(printf '%s\n' "${matching_accounts[@]}" | sed '/^$/d' | sort -u)
   if [ "${#matching_accounts[@]}" -ne 1 ]; then
     echo "ERROR: Expected exactly one non-staging storage account with the three canonical containers. Found ${#matching_accounts[@]}:"
     printf ' - %s\n' "${matching_accounts[@]}"
     exit 1
   fi

   STORAGE_ACCOUNT="${matching_accounts[0]}"
   LEARNER_IDENTITY=$(az account show --query user.name -o tsv)
   echo "STORAGE_ACCOUNT=$STORAGE_ACCOUNT"
   echo "LEARNER_IDENTITY=$LEARNER_IDENTITY"
   ```

6. Continue only if the script prints one `LAB_RG`, one `STORAGE_ACCOUNT`, and the learner identity. If discovery returns zero or multiple matches, stop and report the error to the lab host.

> [!Important]
> This lab intentionally supplies one Microsoft Entra learner identity. Do not sign in as another user or attempt to create an approver. You will prove the boundary by observing denial, not by completing an approval flow.

## Task 2: Verify the vault-to-Resource Guard mapping and choose one protected operation

In this task, you will confirm that the Recovery Services vault is associated with Resource Guard and choose one protected operation for the denial test.

1. In the same Cloud Shell session, resolve exactly one Recovery Services vault and one Resource Guard in the discovered resource group.

   ```bash
   mapfile -t vault_names < <(az backup vault list --resource-group "$LAB_RG" --query "[].name" -o tsv | sed '/^$/d' | sort -u)
   mapfile -t guard_names < <(az dataprotection resource-guard list --resource-group "$LAB_RG" --query "[].name" -o tsv | sed '/^$/d' | sort -u)

   if [ "${#vault_names[@]}" -ne 1 ]; then
     echo "ERROR: Expected exactly one Recovery Services vault in $LAB_RG. Found ${#vault_names[@]}."
     printf ' - %s\n' "${vault_names[@]}"
     exit 1
   fi

   if [ "${#guard_names[@]}" -ne 1 ]; then
     echo "ERROR: Expected exactly one Resource Guard in $LAB_RG. Found ${#guard_names[@]}."
     printf ' - %s\n' "${guard_names[@]}"
     exit 1
   fi

   VAULT_NAME="${vault_names[0]}"
   RESOURCE_GUARD_NAME="${guard_names[0]}"
   VAULT_ID=$(az backup vault show --resource-group "$LAB_RG" --name "$VAULT_NAME" --query id -o tsv)
   RESOURCE_GUARD_ID=$(az dataprotection resource-guard show --resource-group "$LAB_RG" --resource-guard-name "$RESOURCE_GUARD_NAME" --query id -o tsv)

   echo "VAULT_NAME=$VAULT_NAME"
   echo "RESOURCE_GUARD_NAME=$RESOURCE_GUARD_NAME"
   echo "RESOURCE_GUARD_ID=$RESOURCE_GUARD_ID"
   ```

2. Verify that the vault has a Resource Guard mapping and that the mapping references the Resource Guard you just resolved.

   ```bash
   MAPPING_JSON=$(az backup vault resource-guard-mapping show \
     --resource-group "$LAB_RG" \
     --name "$VAULT_NAME" \
     --query "{name:name, resourceGuardId:resourceGuardId, provisioningState:provisioningState}" \
     -o json)

   echo "$MAPPING_JSON" | jq .
   echo "$MAPPING_JSON" | jq -e --arg guardId "$RESOURCE_GUARD_ID" '.resourceGuardId == $guardId' >/dev/null || {
     echo "ERROR: Vault mapping does not reference the resolved Resource Guard."
     exit 1
   }
   ```

3. Inspect the Resource Guard operation configuration briefly.

   ```bash
   az dataprotection resource-guard show \
     --resource-group "$LAB_RG" \
     --resource-guard-name "$RESOURCE_GUARD_NAME" \
     --query "{name:name, criticalOperationExclusionList:criticalOperationExclusionList, resourceGuardOperation:resourceGuardOperation}" \
     -o jsonc
   ```

4. Use **Remove MUA protection** as the single protected operation for this challenge. Microsoft Learn identifies disabling MUA on a Recovery Services vault as Resource Guard-protected and requiring the Backup admin to obtain **Backup MUA Operator** authority on the Resource Guard.
5. In the Azure portal, open the Resource Guard, select **Properties**, and confirm the guard is the same resource named by `RESOURCE_GUARD_NAME`.

> [!Note]
> MUA protects selected Azure Backup critical operations. It does not protect every storage, VM, subscription, or workload administration action.

## Task 3: Check effective access and capture the denial

In this task, you will prove that the learner lacks standing Resource Guard authority and then capture an attributable denial without completing a destructive change.

1. Check your visible role assignments at Resource Guard scope.

   ```bash
   LEARNER_IDENTITY=$(az account show --query user.name -o tsv)
   LEARNER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)

   echo "Learner identity: $LEARNER_IDENTITY"
   echo "Learner object ID: ${LEARNER_OBJECT_ID:-not-readable-from-this-shell}"

   if [ -n "$LEARNER_OBJECT_ID" ]; then
     az role assignment list \
       --assignee "$LEARNER_OBJECT_ID" \
       --scope "$RESOURCE_GUARD_ID" \
       --include-inherited \
       --query "[].{role:roleDefinitionName, scope:scope, principalName:principalName, principalType:principalType}" \
       -o table
   else
     az role assignment list \
       --scope "$RESOURCE_GUARD_ID" \
       --include-inherited \
       --query "[].{role:roleDefinitionName, scope:scope, principalName:principalName, principalType:principalType}" \
       -o table
   fi
   ```

2. In the portal, open the deployed Resource Guard, select **Access control (IAM)**, and use **View my access** for <inject key="AzureAdUserEmail"></inject>.
3. Confirm that the learner does not have standing **Contributor**, **Backup MUA Admin**, or **Backup MUA Operator** on the Resource Guard. If any of those roles appear, stop; the boundary test is invalid because standing guard authority defeats separation.
4. In the Azure portal, open the Recovery Services vault named by `VAULT_NAME`.
5. Open **Properties** and locate **Multi-User Authorization**.
6. Start the update path for Multi-User Authorization and choose the path that would remove MUA protection, such as clearing **Protect with Resource Guard** or removing the Resource Guard association.
7. If prompted for authentication to the Resource Guard directory, authenticate only as the current learner identity <inject key="AzureAdUserEmail"></inject>.
8. Proceed only until the portal reports that Resource Guard access is required, the operation is protected, or the current identity lacks required Resource Guard permission. Record the exact denial text or a concise nonsecret paraphrase.
9. Cancel, close the pane, or navigate back. Do not select any final **Save**, **Update**, **Disable**, **Stop protection**, or equivalent confirmation that would weaken backup protection.
10. Reopen vault **Properties** and confirm MUA remains enabled and still references the Resource Guard.

> [!Important]
> If the portal appears ready to remove MUA protection without a Resource Guard denial, cancel immediately and stop. Do not complete the protected operation.

## Task 4: Upload authorization-boundary JSON evidence

In this task, you will upload one canonical JSON evidence object. The evidence must contain no passwords, tokens, storage keys, connection strings, or screenshots.

1. Run the evidence script. When prompted, paste the denial text or a concise nonsecret paraphrase from Task 3.

   ```bash
   set -euo pipefail

   : "${LAB_RG:?LAB_RG is not set. Rerun Task 1.}"
   : "${STORAGE_ACCOUNT:?STORAGE_ACCOUNT is not set. Rerun Task 1.}"
   : "${VAULT_NAME:?VAULT_NAME is not set. Rerun Task 2.}"
   : "${RESOURCE_GUARD_NAME:?RESOURCE_GUARD_NAME is not set. Rerun Task 2.}"
   : "${RESOURCE_GUARD_ID:?RESOURCE_GUARD_ID is not set. Rerun Task 2.}"

   LEARNER_IDENTITY=$(az account show --query user.name -o tsv)
   read -r -p "Paste the observed Resource Guard denial summary: " DENIAL_SUMMARY

   if [ -z "$DENIAL_SUMMARY" ]; then
     echo "ERROR: denial summary cannot be empty."
     exit 1
   fi

   mkdir -p challenge-03-evidence
   EVIDENCE_FILE="challenge-03-evidence/authorization-boundary.json"
   OBSERVED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

   jq -n \
     --arg resourceGroup "$LAB_RG" \
     --arg vaultName "$VAULT_NAME" \
     --arg resourceGuardName "$RESOURCE_GUARD_NAME" \
     --arg resourceGuardId "$RESOURCE_GUARD_ID" \
     --arg learnerIdentity "$LEARNER_IDENTITY" \
     --arg observedUtc "$OBSERVED_UTC" \
     --arg denialSummary "$DENIAL_SUMMARY" \
     '{
       challenge: "03",
       evidenceType: "authorization-boundary",
       resourceGroup: $resourceGroup,
       vaultName: $vaultName,
       resourceGuardName: $resourceGuardName,
       resourceGuardId: $resourceGuardId,
       learnerIdentity: $learnerIdentity,
       protectedOperation: "Remove MUA protection",
       authorizationResult: "Denied",
       denialObserved: true,
       denialSummary: $denialSummary,
       observedUtc: $observedUtc,
       conceptualExplanation: {
         separateApproverIdentity: "Production MUA needs a separate security approver with Resource Guard authority, not the same vault admin identity.",
         backupMuaOperatorEligibleAssignment: "The requester should receive an eligible Backup MUA Operator assignment at Resource Guard scope only when protected work is needed.",
         pimActivationWithApproval: "The requester activates the eligible role through Microsoft Entra PIM and a configured approver approves the request before the protected operation is allowed.",
         timeBoundActivation: "Approved Resource Guard authority should be time-bound and expire after the maintenance window.",
         standingAccessRisk: "Standing Contributor, Backup MUA Admin, or Backup MUA Operator on the guard lets a compromised vault admin satisfy or weaken the boundary.",
         ransomwarePreventionValue: "The separated guard authority can block or delay ransomware from removing MUA or disabling backup security settings after vault compromise.",
         notPerformedReason: "This lab provides one Microsoft Entra learner identity and no separate approver or PIM approval workflow, so approval is described rather than performed.",
         requirementsToPerform: "Use a separate approver, configure eligible Backup MUA Operator, require approval-controlled PIM activation, approve a time-bound request, perform the operation, and let access expire."
       },
       secretsIncluded: false
     }' > "$EVIDENCE_FILE"

   jq . "$EVIDENCE_FILE"

   az storage blob upload \
     --account-name "$STORAGE_ACCOUNT" \
     --container-name "lab-evidence" \
     --name "challenge-03/authorization-boundary.json" \
     --file "$EVIDENCE_FILE" \
     --auth-mode login \
     --overwrite true \
     -o table
   ```

2. Verify the upload at the canonical path.

   ```bash
   az storage blob show \
     --account-name "$STORAGE_ACCOUNT" \
     --container-name "lab-evidence" \
     --name "challenge-03/authorization-boundary.json" \
     --auth-mode login \
     --query "{name:name, size:properties.contentLength, lastModified:properties.lastModified}" \
     -o table
   ```

3. Confirm the JSON has these non-empty values:
   - `protectedOperation`: `Remove MUA protection`
   - `authorizationResult`: `Denied`
   - `denialObserved`: `true`
   - `denialSummary`: the attributable denial you observed
   - `conceptualExplanation.separateApproverIdentity`
   - `conceptualExplanation.backupMuaOperatorEligibleAssignment`
   - `conceptualExplanation.pimActivationWithApproval`
   - `conceptualExplanation.timeBoundActivation`
   - `conceptualExplanation.standingAccessRisk`
   - `conceptualExplanation.ransomwarePreventionValue`
   - `conceptualExplanation.notPerformedReason`
   - `conceptualExplanation.requirementsToPerform`
   - `secretsIncluded`: `false`

## Summary

You proved the Resource Guard authorization boundary without completing a destructive change. You resolved the lab resources deterministically, verified the vault mapping, selected **Remove MUA protection** as the protected operation, confirmed the learner lacks standing guard authority, captured an attributable Resource Guard denial, canceled safely, and uploaded the canonical authorization-boundary JSON evidence.
