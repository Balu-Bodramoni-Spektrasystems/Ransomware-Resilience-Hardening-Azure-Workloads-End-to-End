# Challenge 5: Investigate the ransomware signal and rotate access

### Estimated Duration: 25 Minutes

## Scenario

The deployment-time benign encryption mimic already targeted `containera-unprotected`. You will investigate the resulting storage signal, use the planned Defender for Storage fallback when no alert is visible, and rotate storage account keys without exposing secrets.

## Overview

You will deterministically discover the primary lab/evidence storage account, check Microsoft Defender for Cloud for a Defender for Storage alert, complete the valid fallback by verifying `Microsoft.Security/defenderForStorageSettings/current` with API `2025-01-01` and hunting telemetry when needed, then rotate the impacted access key and verify old/new behavior. You will record only one concise investigation/containment note and upload the required JSON markers to `lab-evidence`.

## Objectives

- Task 1: Discover the primary lab/evidence storage account
- Task 2: Investigate Defender for Storage or complete the valid fallback
- Task 3: Rotate and verify the storage account keys
- Task 4: Record one concise containment follow-up

## Task 1: Discover the primary lab/evidence storage account

In this task, you will sign in and resolve the exact resource group and primary lab/evidence storage account. Discovery must be deterministic: use deployment tags, exclude the dedicated restore staging account, require all three canonical containers, and continue only when exactly one non-staging storage account matches.

1. Sign in to the Azure portal at <https://portal.azure.com>.
   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
   - Subscription: <inject key="SubscriptionID"></inject>
   - Tenant: <inject key="TenantID"></inject>

2. Open Azure Cloud Shell, or another terminal with Azure CLI and `jq`, and confirm the active subscription.

   ```bash
   az account show --query "{name:name, id:id, tenantId:tenantId}" -o table
   ```

3. Copy your deployment identifier from this page: **<inject key="DeploymentID" enableCopy="false"/>**. When prompted, paste that value. Resolve the resource group from exact deployment tags only.

   ```bash
   read -p "Paste your Deployment ID: " DID

   RG_CANDIDATES=$(mktemp)
   RESOURCE_RG_CANDIDATES=$(mktemp)

   az group list --tag "deploymentId=${DID}" --query "[].name" -o tsv >> "$RG_CANDIDATES"
   az group list --tag "DeploymentID=${DID}" --query "[].name" -o tsv >> "$RG_CANDIDATES"
   sort -u "$RG_CANDIDATES" -o "$RG_CANDIDATES"
   RG_COUNT=$(grep -cve '^$' "$RG_CANDIDATES" || true)

   if [ "$RG_COUNT" -eq 0 ]; then
     az resource list --tag "deploymentId=${DID}" --query "[].resourceGroup" -o tsv >> "$RESOURCE_RG_CANDIDATES"
     az resource list --tag "DeploymentID=${DID}" --query "[].resourceGroup" -o tsv >> "$RESOURCE_RG_CANDIDATES"
     sort -u "$RESOURCE_RG_CANDIDATES" -o "$RESOURCE_RG_CANDIDATES"
     RG_COUNT=$(grep -cve '^$' "$RESOURCE_RG_CANDIDATES" || true)
     if [ "$RG_COUNT" -ne 1 ]; then
       echo "ERROR: Expected exactly one resource group from exact deployment tags. Found $RG_COUNT." >&2
       cat "$RESOURCE_RG_CANDIDATES" >&2
       exit 1
     fi
     RG=$(cat "$RESOURCE_RG_CANDIDATES")
   elif [ "$RG_COUNT" -eq 1 ]; then
     RG=$(cat "$RG_CANDIDATES")
   else
     echo "ERROR: Expected exactly one tagged resource group. Found $RG_COUNT." >&2
     cat "$RG_CANDIDATES" >&2
     exit 1
   fi

   echo "Resource group: $RG"
   ```

4. Copy the dedicated restore staging storage account name from this page: <inject key="restoreStagingStorageAccountName"></inject>. When prompted, paste it. Then discover the primary lab/evidence storage account by required container membership.

   ```bash
   read -p "Paste the dedicated restore staging storage account name: " RESTORE_STAGE_SA

   CONTAINERA_UNPROTECTED="containera-unprotected"
   CONTAINERB_PROTECTME="containerb-protectme"
   EVIDENCE_CONTAINER="lab-evidence"

   STORAGE_ACCOUNTS_JSON=$(mktemp)
   SA_CANDIDATES=$(mktemp)
   SA_CANDIDATES_SORTED=$(mktemp)

   az storage account list -g "$RG" --query "[].{name:name,id:id}" -o json > "$STORAGE_ACCOUNTS_JSON"

   if ! jq -e --arg stage "$RESTORE_STAGE_SA" '.[] | select(.name == $stage)' "$STORAGE_ACCOUNTS_JSON" >/dev/null; then
     echo "ERROR: Restore staging account '$RESTORE_STAGE_SA' was not found in resource group '$RG'." >&2
     jq -r '.[].name' "$STORAGE_ACCOUNTS_JSON" >&2
     exit 1
   fi

   while IFS=$'\t' read -r ACCOUNT_NAME ACCOUNT_ID; do
     [ -z "$ACCOUNT_NAME" ] && continue
     if [ "$ACCOUNT_NAME" = "$RESTORE_STAGE_SA" ]; then
       echo "Excluding restore staging account: $ACCOUNT_NAME"
       continue
     fi

     CONTAINER_NAMES=$(mktemp)
     if ! az storage container list --account-name "$ACCOUNT_NAME" --auth-mode login --query "[].name" -o tsv > "$CONTAINER_NAMES"; then
       echo "Skipping '$ACCOUNT_NAME': could not list containers with Microsoft Entra authorization." >&2
       continue
     fi

     if grep -Fxq "$CONTAINERA_UNPROTECTED" "$CONTAINER_NAMES" && \
        grep -Fxq "$CONTAINERB_PROTECTME" "$CONTAINER_NAMES" && \
        grep -Fxq "$EVIDENCE_CONTAINER" "$CONTAINER_NAMES"; then
       printf '%s\t%s\n' "$ACCOUNT_NAME" "$ACCOUNT_ID" >> "$SA_CANDIDATES"
     fi
   done < <(jq -r '.[] | [.name, .id] | @tsv' "$STORAGE_ACCOUNTS_JSON")

   sort -u "$SA_CANDIDATES" > "$SA_CANDIDATES_SORTED"
   SA_COUNT=$(grep -cve '^$' "$SA_CANDIDATES_SORTED" || true)
   if [ "$SA_COUNT" -ne 1 ]; then
     echo "ERROR: Expected exactly one non-staging storage account containing $CONTAINERA_UNPROTECTED, $CONTAINERB_PROTECTME, and $EVIDENCE_CONTAINER. Found $SA_COUNT." >&2
     cat "$SA_CANDIDATES_SORTED" >&2
     exit 1
   fi

   SA=$(cut -f1 "$SA_CANDIDATES_SORTED")
   SA_ID=$(cut -f2 "$SA_CANDIDATES_SORTED")

   echo "Primary lab/evidence storage account: $SA"
   echo "Primary lab/evidence storage account ID: $SA_ID"
   echo "Excluded restore staging account: $RESTORE_STAGE_SA"

   az storage container list --account-name "$SA" --auth-mode login --query "[].name" -o table
   ```

5. Confirm `containera-unprotected` has blob state you can use during investigation.

   ```bash
   az storage blob list \
     --account-name "$SA" \
     --auth-mode login \
     --container-name "$CONTAINERA_UNPROTECTED" \
     --query "[].{name:name, lastModified:properties.lastModified, size:properties.contentLength}" \
     -o table
   ```

> [!Note]
> The lab uses a benign encryption-mimic script. Treat it as ransomware-style tampering evidence for investigation practice, but do not claim malware was detected unless a Defender alert actually appears.

## Task 2: Investigate Defender for Storage or complete the valid fallback

In this task, you will first use the Defender alert path. If no relevant alert is visible, you will complete the fallback route by verifying the account-scoped Defender for Storage configuration and performing manual hunting. Defender alerts can be asynchronous, and the benign overwrite mimic may not generate an alert during the lab window.

1. In the Azure portal, open **Microsoft Defender for Cloud** > **Security alerts**.

2. Filter to the lab subscription, the resource group stored in `$RG`, and the primary lab/evidence storage account stored in `$SA`.

3. Look for Azure Storage alerts related to suspicious blob access, unusual delete or write activity, anomalous access, overly permissive SAS usage, account key exposure, or malware-related upload/download findings.

4. If a relevant alert exists, record a compact alert outcome with only these fields in your notes:
   - `defenderAlertStatus`: `alert-found`
   - `alertTitle`
   - `severity`
   - `affectedResource`
   - `activityTime`
   - `suspectedPattern`
   - `mentionsContaineraUnprotected`: `true` or `false`

5. If no relevant alert exists, read the ARM-deployed account-scoped Defender for Storage resource. This is the required configuration check for the fallback route: `${SA_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2025-01-01`.

   ```bash
   DEFENDER_SETTING_URI="https://management.azure.com${SA_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2025-01-01"
   echo "Reading: $DEFENDER_SETTING_URI"

   az rest --method get --uri "$DEFENDER_SETTING_URI" -o json > defender-storage-current.json

   DEFENDER_ENABLED=$(jq -r '.properties.isEnabled // empty' defender-storage-current.json)
   if [ "$DEFENDER_ENABLED" != "true" ]; then
     echo "ERROR: Defender for Storage current resource exists, but properties.isEnabled is not true." >&2
     jq '{id,name,type,properties}' defender-storage-current.json >&2
     exit 1
   fi

   jq '{
     id,
     name,
     type,
     defenderForStorageEnabled: .properties.isEnabled,
     overrideSubscriptionLevelSettings: .properties.overrideSubscriptionLevelSettings,
     malwareScanningOnUploadEnabled: .properties.malwareScanning.onUpload.isEnabled,
     malwareScanningCapGBPerMonth: .properties.malwareScanning.onUpload.capGBPerMonth,
     scanResultsEventGridTopicResourceId: .properties.malwareScanning.scanResultsEventGridTopicResourceId,
     sensitiveDataDiscoveryEnabled: .properties.sensitiveDataDiscovery.isEnabled
   }' defender-storage-current.json
   ```

6. Continue the fallback route by checking Blob service diagnostic settings and hunting StorageBlobLogs when a Log Analytics workspace is attached.

   ```bash
   BLOB_SERVICE_ID="${SA_ID}/blobServices/default"
   LAW_IDS_FILE=$(mktemp)

   az monitor diagnostic-settings list --resource "$BLOB_SERVICE_ID" -o table
   az monitor diagnostic-settings list --resource "$BLOB_SERVICE_ID" --query "[?workspaceId != null].workspaceId" -o tsv | sort -u > "$LAW_IDS_FILE"

   QUERY=$(cat <<KQL
   StorageBlobLogs
   | where TimeGenerated > ago(8h)
   | where AccountName =~ '$SA'
   | extend ContainerName = tostring(split(parse_url(Uri).Path, "/")[1])
   | where ContainerName in ("containera-unprotected", "containerb-protectme")
   | where OperationName has_any ('PutBlob','PutBlock','PutBlockList','DeleteBlob','SetBlobMetadata','SetBlobTier') or Category in ('StorageWrite','StorageDelete') or toint(StatusCode) between (400 .. 499)
   | summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by ContainerName, OperationName, StatusCode, StatusText, AuthenticationType
   | order by LastSeen desc
   KQL
   )

   if [ -s "$LAW_IDS_FILE" ]; then
     while IFS= read -r LAW_ID; do
       [ -z "$LAW_ID" ] && continue
       LAW_CID=$(az resource show --ids "$LAW_ID" --query "properties.customerId" -o tsv 2>/dev/null)
       if [ -n "$LAW_CID" ]; then
         echo "Running manual hunting query against workspace: $LAW_ID"
         az monitor log-analytics query --workspace "$LAW_CID" --analytics-query "$QUERY" -o table
       fi
     done < "$LAW_IDS_FILE"
   else
     echo "No Log Analytics workspace attached to Blob service diagnostics. Use storage state and script-output evidence as fallback hunting evidence."
   fi
   ```

7. For fallback hunting, also compare current storage state for `containera-unprotected` with the attack-script output from Challenge 4 or deployment evidence. Keep this as a short note; do not create a second narrative summary.

8. If you used the fallback route, upload the required marker `challenge-05/manual-hunting-pending.json` to `lab-evidence`. This schema is required, and it must not contain secrets.

   ```bash
   LOG_WORKSPACE_PRESENT="false"
   if [ -s "$LAW_IDS_FILE" ]; then LOG_WORKSPACE_PRESENT="true"; fi

   cat > manual-hunting-pending.json <<EOF
   {
     "challenge": "05",
     "evidenceType": "manual-hunting-pending",
     "defenderAlertStatus": "pending-or-not-generated",
     "reason": "No relevant Defender for Storage alert was visible during the lab investigation, or the benign overwrite mimic did not produce an alert.",
     "resourceGroup": "${RG}",
     "storageAccount": "${SA}",
     "containera-unprotected": "${CONTAINERA_UNPROTECTED}",
     "containerb-protectme": "${CONTAINERB_PROTECTME}",
     "defenderForStorageEnabled": ${DEFENDER_ENABLED},
     "defenderForStorageResource": "${SA_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2025-01-01",
     "logAnalyticsWorkspacePresent": "${LOG_WORKSPACE_PRESENT}",
     "huntingPerformed": [
       "ARM-deployed Microsoft.Security/defenderForStorageSettings/current configuration verified with API 2025-01-01",
       "Blob service diagnostic settings",
       "StorageBlobLogs when available",
       "container state",
       "attack-script output"
     ],
     "secretsIncluded": false,
     "recordedUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   }
   EOF

   az storage blob upload \
     --account-name "$SA" \
     --auth-mode login \
     --container-name "$EVIDENCE_CONTAINER" \
     --name "challenge-05/manual-hunting-pending.json" \
     --file manual-hunting-pending.json \
     --overwrite true \
     -o table
   ```

> [!Important]
> The fallback is a valid planned completion path only when you verify `Microsoft.Security/defenderForStorageSettings/current` at API `2025-01-01`, confirm `properties.isEnabled` is `true`, perform manual hunting, and upload the marker above.

## Task 3: Rotate and verify the storage account keys

In this task, you will rotate the impacted storage account access key and prove that the old primary key is rejected while the new primary key works. Azure Storage has two account keys so clients can be moved before a key is regenerated.

1. List key metadata without recording key values.

   ```bash
   az storage account keys list -g "$RG" -n "$SA" --query "[].{keyName:keyName, permissions:permissions, creationTime:creationTime}" -o table
   ```

2. Retrieve key2 only for a temporary continuity test, then confirm it can list containers. Do not paste key values into notes or evidence.

   ```bash
   KEY2=$(az storage account keys list -g "$RG" -n "$SA" --query "[?keyName=='key2'].value | [0]" -o tsv)
   if [ -z "$KEY2" ]; then echo "ERROR: key2 was not returned." >&2; exit 1; fi

   az storage container list --account-name "$SA" --account-key "$KEY2" --query "[].name" -o table
   ```

3. Capture the current key1 in memory for the rejection test, regenerate key1, and verify old key1 fails.

   ```bash
   OLD_KEY1=$(az storage account keys list -g "$RG" -n "$SA" --query "[?keyName=='key1'].value | [0]" -o tsv)
   if [ -z "$OLD_KEY1" ]; then echo "ERROR: key1 was not returned." >&2; exit 1; fi

   az storage account keys renew -g "$RG" -n "$SA" --key primary

   echo "Testing old key1. Authorization failure is expected."
   set +e
   az storage container list --account-name "$SA" --account-key "$OLD_KEY1" --query "[].name" -o table >/tmp/old-key-test.out 2>/tmp/old-key-test.err
   OLD_KEY_STATUS=$?
   set -e

   if [ "$OLD_KEY_STATUS" -ne 0 ]; then
     OLD_KEY_RESULT="old-key-rejected"
     head -n 3 /tmp/old-key-test.err
   else
     OLD_KEY_RESULT="old-key-still-authorized"
     cat /tmp/old-key-test.out
   fi
   echo "Old key test result: $OLD_KEY_RESULT"
   ```

4. Retrieve the new key1 and verify it works.

   ```bash
   NEW_KEY1=$(az storage account keys list -g "$RG" -n "$SA" --query "[?keyName=='key1'].value | [0]" -o tsv)
   if [ -z "$NEW_KEY1" ]; then echo "ERROR: new key1 was not returned." >&2; exit 1; fi

   set +e
   az storage container list --account-name "$SA" --account-key "$NEW_KEY1" --query "[].name" -o table >/tmp/new-key-test.out 2>/tmp/new-key-test.err
   NEW_KEY_STATUS=$?
   set -e

   if [ "$NEW_KEY_STATUS" -eq 0 ]; then
     NEW_KEY_RESULT="new-key-authorized"
     cat /tmp/new-key-test.out
   else
     NEW_KEY_RESULT="new-key-failed"
     head -n 3 /tmp/new-key-test.err
   fi
   echo "New key test result: $NEW_KEY_RESULT"

   if [ "$OLD_KEY_RESULT" != "old-key-rejected" ] || [ "$NEW_KEY_RESULT" != "new-key-authorized" ]; then
     echo "ERROR: Key rotation verification did not produce the required old/new behavior." >&2
     exit 1
   fi
   ```

5. Regenerate key2 to complete a two-key rotation for the lab account, then upload the required marker `challenge-05/key-rotation-verified.json`. This schema is required, and it must not contain key values.

   ```bash
   az storage account keys renew -g "$RG" -n "$SA" --key secondary

   cat > key-rotation-verified.json <<EOF
   {
     "challenge": "05",
     "evidenceType": "key-rotation-verified",
     "resourceGroup": "${RG}",
     "storageAccount": "${SA}",
     "rotatedPrimaryKey": true,
     "oldPrimaryKeyResult": "${OLD_KEY_RESULT}",
     "newPrimaryKeyResult": "${NEW_KEY_RESULT}",
     "secondaryRotationAttempted": true,
     "verifiedContainerListingScope": "container list only; no key values recorded",
     "secretsIncluded": false,
     "recordedUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   }
   EOF

   az storage blob upload \
     --account-name "$SA" \
     --account-key "$NEW_KEY1" \
     --container-name "$EVIDENCE_CONTAINER" \
     --name "challenge-05/key-rotation-verified.json" \
     --file key-rotation-verified.json \
     --overwrite true \
     -o table
   ```

> [!Important]
> In production, regenerating storage account keys can break clients that still use those keys and revokes account SAS or service SAS tokens signed with the regenerated key. Prefer Microsoft Entra ID or managed identities where possible.

## Task 4: Record one concise containment follow-up

In this task, you will create one short investigation and containment note. This replaces duplicate narrative recording and second summaries.

1. Create or update a note named `challenge-05-investigation-summary.md` in your working folder.

2. Include only these fields:
   - **Storage discovery:** exact deployment tag resource group discovery; restore staging account excluded; required containers `containera-unprotected`, `containerb-protectme`, and `lab-evidence`; exactly one deduplicated primary account found.
   - **Alert path:** Defender alert found, or fallback completed with `Microsoft.Security/defenderForStorageSettings/current@2025-01-01`, `properties.isEnabled=true`, manual hunting, and `challenge-05/manual-hunting-pending.json` uploaded.
   - **Signal reviewed:** Defender alert details when present; otherwise Blob service diagnostic settings, StorageBlobLogs when available, container state, and attack-script output.
   - **Key rotation:** old key1 rejected, new key1 authorized, key2 rotation attempted, and `challenge-05/key-rotation-verified.json` uploaded.
   - **Follow-up:** remove hard-coded keys, regenerate affected SAS tokens, update dependent connection strings, prefer Microsoft Entra ID authorization, keep watching Defender for Cloud alerts and StorageBlobLogs, and investigate repeated unauthorized attempts.

3. Do not include passwords, storage keys, connection strings, SAS tokens, or copied secret material.

4. Do not run a Challenge 5 validation here. The final validation for investigation and recovery occurs after Challenge 6 because it also depends on restore evidence.

## Summary

You investigated the storage ransomware signal through Defender for Storage or the valid configuration-plus-hunting fallback, uploaded required markers when applicable, rotated storage account keys, verified old/new key behavior, and recorded one concise containment follow-up without exposing secrets.