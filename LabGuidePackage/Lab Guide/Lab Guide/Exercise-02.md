# Challenge 2 — Harden Container B against tampering

### Estimated Duration: 25 minutes

## Scenario

Container A, **containera-unprotected**, was attacked automatically during deployment and remains the intentionally vulnerable positive control. In this challenge, you will protect only Container B, **containerb-protectme**, before the same benign encryption-mimic is run against it later. Your goal is narrow and deliberate: create a container-level time-based immutability policy on Container B, verify that Container A and the storage account itself were not protected by mistake, and record the unlocked-policy limitation.

## Overview

You will deterministically discover the lab resource group and primary storage account for **deployment <inject key="DeploymentID" enableCopy="false"/>** by using exact deployment tags and the three canonical containers. You will configure a short, unlocked, container-scoped time-based immutability policy on **containerb-protectme** only. You will consolidate verification into one compact evidence record and briefly note the deployed Defender for Storage resource plus the review-only VM controls that are out of scope for this lab.

## Objectives

- Task 1: Discover the primary storage account deterministically
- Task 2: Configure B-only container-level immutability
- Task 3: Record consolidated verification and architecture notes
- Task 4: Validate tamper protections

## Task 1: Discover the primary storage account deterministically

In this task, you will find the resource group and primary storage account without relying on generated names or portal ordering. The correct primary storage account is the one non-staging storage account in the lab resource group that contains **containera-unprotected**, **containerb-protectme**, and **lab-evidence**.

1. Sign in to the Azure portal at https://portal.azure.com with the lab identity.
   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
   - Subscription: <inject key="SubscriptionID"></inject>
   - Tenant: <inject key="TenantID"></inject>
2. Open **Cloud Shell** and select **Bash**.
3. If prompted, use the current lab subscription context. Then run this discovery script. When prompted, paste deployment ID <inject key="DeploymentID" enableCopy="false"/> and restore staging storage account name <inject key="restoreStagingStorageAccountName"></inject>.

   ```bash
   read -r -p "Paste the CloudLabs deployment ID: " deploymentId
   read -r -p "Paste the restore staging storage account name: " restoreStagingStorageAccountName

   rgMatches=$(az group list --tag "deploymentId=$deploymentId" --query "[].name" -o tsv)
   rgMatchesUpper=$(az group list --tag "DeploymentID=$deploymentId" --query "[].name" -o tsv)
   combinedResourceGroups=$(printf "%s\n%s\n" "$rgMatches" "$rgMatchesUpper" | sed '/^$/d' | sort -u)

   if [ -z "$combinedResourceGroups" ]; then
     resourceMatches=$(az resource list --tag "deploymentId=$deploymentId" --query "[].resourceGroup" -o tsv)
     resourceMatchesUpper=$(az resource list --tag "DeploymentID=$deploymentId" --query "[].resourceGroup" -o tsv)
     combinedResourceGroups=$(printf "%s\n%s\n" "$resourceMatches" "$resourceMatchesUpper" | sed '/^$/d' | sort -u)
   fi

   resourceGroupCount=$(printf "%s\n" "$combinedResourceGroups" | sed '/^$/d' | wc -l | tr -d ' ')
   if [ "$resourceGroupCount" -ne 1 ]; then
     echo "ERROR: Expected exactly one resource group for this deployment ID; found $resourceGroupCount."
     printf "%s\n" "$combinedResourceGroups"
     exit 1
   fi

   export LAB_RG="$combinedResourceGroups"
   echo "Discovered lab resource group: $LAB_RG"

   storageAccounts=$(az resource list \
     --resource-group "$LAB_RG" \
     --resource-type Microsoft.Storage/storageAccounts \
     --query "[].name" \
     --output tsv | sed '/^$/d' | sort -u)

   matchingAccounts=""
   while IFS= read -r accountName; do
     [ -z "$accountName" ] && continue
     if [ "$accountName" = "$restoreStagingStorageAccountName" ]; then
       echo "Excluded restore staging storage account: $accountName"
       continue
     fi

     containerNames=$(az storage container list \
       --account-name "$accountName" \
       --auth-mode login \
       --query "[].name" \
       --output tsv 2>/tmp/container-list-error.txt)

     if [ $? -ne 0 ]; then
       echo "Skipped $accountName because container listing failed."
       cat /tmp/container-list-error.txt
       continue
     fi

     if printf "%s\n" "$containerNames" | grep -Fxq "containera-unprotected" && \
        printf "%s\n" "$containerNames" | grep -Fxq "containerb-protectme" && \
        printf "%s\n" "$containerNames" | grep -Fxq "lab-evidence"; then
       matchingAccounts=$(printf "%s\n%s\n" "$matchingAccounts" "$accountName")
     fi
   done <<ACCOUNT_LIST
   $storageAccounts
   ACCOUNT_LIST

   matchingAccounts=$(printf "%s\n" "$matchingAccounts" | sed '/^$/d' | sort -u)
   matchingAccountCount=$(printf "%s\n" "$matchingAccounts" | sed '/^$/d' | wc -l | tr -d ' ')
   if [ "$matchingAccountCount" -ne 1 ]; then
     echo "ERROR: Expected exactly one non-staging primary storage account with all three canonical containers; found $matchingAccountCount."
     printf "%s\n" "$matchingAccounts"
     exit 1
   fi

   export STORAGE_ACCOUNT="$matchingAccounts"
   echo "Discovered primary storage account: $STORAGE_ACCOUNT"
   ```

4. Confirm the output shows exactly one **LAB_RG** and one **STORAGE_ACCOUNT**. Do not guess if the script reports zero or multiple matches.
5. Verify the three canonical containers in the discovered account.

   ```bash
   az storage container list \
     --account-name "$STORAGE_ACCOUNT" \
     --auth-mode login \
     --query "[].name" \
     --output table
   ```

> [!Important]
> The primary storage account is resolved by exact deployment tags plus container evidence. Do not select a storage account by name similarity, list position, or memory from another lab run.

## Task 2: Configure B-only container-level immutability

In this task, you will create a time-based immutability policy on **containerb-protectme** only. The policy must be scoped to the container, not the storage account, and Container A must remain unprotected.

1. In the Azure portal, open the resource group reported as **LAB_RG**.
2. Open the storage account reported as **STORAGE_ACCOUNT**.
3. Select **Data storage** > **Containers**.
4. Select **containerb-protectme**.
5. Open **Access policy**.
6. In the **Immutable blob storage** section, add a policy with these settings:
   - **Policy type:** Time-based retention.
   - **Retention period:** 1 day.
   - **Scope:** Container. Do not enable version-level immutability.
   - **Legal hold:** Not configured.
   - **Protected append writes:** Leave disabled unless the portal requires an explicit choice.
   - **Policy state:** Leave unlocked for this lab.
7. Save the policy.
8. Do not lock the policy. Do not enable account-level immutability. Do not add a policy to **containera-unprotected**.

> [!Note]
> Azure Blob Storage immutability policies protect blob data from overwrite and delete operations for the configured interval. In this lab, the policy is intentionally left unlocked so the later challenges can focus on ransomware-resilience reasoning without creating a long-lived compliance lock in the sandbox.

> [!Important]
> An unlocked time-based immutability policy is tamper resistance, not absolute protection. An authorized principal with the required permissions can modify or remove an unlocked policy. That limitation must appear in your evidence.

## Task 3: Record consolidated verification and architecture notes

In this task, you will create one compact evidence record instead of separate long investigations. The evidence must prove B-only immutability, no A policy, no account-level policy, and the brief architecture context for Defender and VM controls.

1. Keep using the same Cloud Shell session where **LAB_RG** and **STORAGE_ACCOUNT** are set.
2. Run the following commands to collect verification values.

   ```bash
   echo "Resource group: $LAB_RG"
   echo "Primary storage account: $STORAGE_ACCOUNT"

   echo "--- Container B immutability policy ---"
   az storage container immutability-policy show \
     --resource-group "$LAB_RG" \
     --account-name "$STORAGE_ACCOUNT" \
     --container-name containerb-protectme \
     --query "{periodDays:immutabilityPeriodSinceCreationInDays,state:state,etag:etag}" \
     --output json

   echo "--- Container A immutability policy check; expected to fail with NotFound or show no policy ---"
   az storage container immutability-policy show \
     --resource-group "$LAB_RG" \
     --account-name "$STORAGE_ACCOUNT" \
     --container-name containera-unprotected \
     --output json

   echo "--- Account-level immutability; expected false or null ---"
   az storage account show \
     --resource-group "$LAB_RG" \
     --name "$STORAGE_ACCOUNT" \
     --query "immutableStorageWithVersioning.enabled" \
     --output tsv

   echo "--- Defender for Storage extension resource ---"
   az resource show \
     --resource-group "$LAB_RG" \
     --namespace Microsoft.Security \
     --resource-type defenderForStorageSettings \
     --name current \
     --parent "Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT" \
     --api-version 2025-01-01 \
     --query "{type:type,name:name,isEnabled:properties.isEnabled,apiVersion:'2025-01-01'}" \
     --output json
   ```

3. If the Container A policy command returns an error because the policy does not exist, treat that as the expected result. Do not add a policy to Container A to make the command succeed.
4. Create a concise evidence note in your own scratch file or lab notes using this structure:
   - **Primary storage account:** the discovered **STORAGE_ACCOUNT** value.
   - **Protected container:** **containerb-protectme** has an unlocked container-scoped time-based retention policy with a retention period greater than 0 days.
   - **Unprotected positive control:** **containera-unprotected** has no immutability policy.
   - **No account policy:** account-level immutability is false or not set.
   - **Unlocked-policy caveat:** an authorized principal can modify or remove an unlocked policy, so this is not absolute protection.
   - **Defender resource note:** the lab includes **Microsoft.Security/defenderForStorageSettings/current** at API **2025-01-01** as the storage-focused detection resource.
   - **Review-only VM note:** JIT VM access, file integrity monitoring, and broader server monitoring are useful production controls, but they are not configured in this challenge because their Defender for Servers Plan 2 and onboarding prerequisites are outside this lab scope.

> [!Tip]
> Keep the evidence short. Challenge 4 is where you will perform the deeper attack-output, blob-state, and Blob service log correlation.

## Task 4: Validate tamper protections

In this task, you will run the challenge validation after confirming the exact intended scope.

1. Before validating, confirm these final conditions:
   - **containerb-protectme** has an active container-level time-based immutability policy.
   - **containera-unprotected** has no immutability policy.
   - The primary storage account does not have account-level immutability enabled.
   - You did not enable version-level immutability for Container B.
   - You did not configure JIT VM access, file integrity monitoring, or subscription-wide Defender for Servers Plan 2 as part of this challenge.
2. Run the validation.

<validation step="Tamper protections enabled"/>

## Summary

You deterministically found the primary storage account for **deployment <inject key="DeploymentID" enableCopy="false"/>**, configured a short unlocked container-level time-based immutability policy on **containerb-protectme** only, verified that **containera-unprotected** and the storage account itself remain without immutability policy, recorded the unlocked-policy caveat, and kept Defender and VM monitoring controls to a brief architecture note. Container B is now ready for the controlled attack comparison in Challenge 4.
