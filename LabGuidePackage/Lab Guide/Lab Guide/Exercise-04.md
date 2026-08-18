# Challenge 4 — Attack Container B and prove protection blocked tampering

### Estimated Duration: 30 Minutes

## Scenario

Container A was attacked automatically during deployment and intentionally remains unprotected. Container B began with the same seeded blobs, but you hardened it in Challenge 2 with a **container-level** time-based immutability policy. In this challenge, you will run the same benign encryption-mimic script against Container B and prove that the same attempted writes succeeded against A but were rejected against B.

## Overview

You will collect one compact mixed-evidence record instead of several separate narrative exports. The required proof has three evidence sources: script output, blob state/checksum comparison, and Blob service logs or diagnostics. Your conclusion must also preserve the key caveat: an unlocked immutability policy can be changed or removed by an authorized principal, so it is tamper-resistant for this test, not absolute protection against all administrators.

If your portal session has expired, sign in to <https://portal.azure.com> with:

- User name: <inject key="AzureAdUserEmail"></inject>
- Password: <inject key="AzureAdUserPassword"></inject>

Your subscription is <inject key="SubscriptionID"></inject>. Use deployment id <inject key="DeploymentID" enableCopy="false"/> to discover the primary lab resource group instead of assuming a hard-coded resource-group name.

## Objectives

- Task 1: Deterministically discover the primary lab/evidence storage account and diagnostic scope.
- Task 2: Confirm Container A positive-control counters and run the mimic against Container B.
- Task 3: Build one compact evidence matrix from script output, blob state/checksums, and Blob service logs/diagnostics.
- Task 4: Upload the canonical Container B output and validate the challenge.

## Task 1: Discover the lab resources and diagnostic scope

In this task, you will identify the exact resource group, primary storage account, Blob service diagnostic scope, and Log Analytics workspace used for evidence. The primary storage account is the only non-staging storage account in the exact lab resource group that contains all three canonical containers: `containera-unprotected`, `containerb-protectme`, and `lab-evidence`.

1. Connect to the operator VM and open **PowerShell** as an administrator.

2. Confirm the Azure CLI context.

   ```powershell
   az account show --query "{name:name, id:id, tenantId:tenantId}" -o table
   ```

3. Initialize the evidence workspace. When prompted, paste deployment id <inject key="DeploymentID" enableCopy="false"/> and restore staging storage account <inject key="restoreStagingStorageAccountName"></inject>.

   ```powershell
   $EvidenceRoot = "C:\LabFiles\RansomwareResilience\Evidence\challenge-04"
   New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

   $DID = Read-Host "Paste your CloudLabs deployment id"
   $RestoreStagingStorageAccountName = Read-Host "Paste the dedicated restore staging storage account name"

   $ContainerA = "containera-unprotected"
   $ContainerB = "containerb-protectme"
   $EvidenceContainer = "lab-evidence"
   $RequiredContainers = @($ContainerA, $ContainerB, $EvidenceContainer)
   $MimicScript = "C:\LabFiles\RansomwareResilience\Scripts\Invoke-BenignBlobEncryptionMimic.ps1"
   $ContainerAEvidence = "C:\LabFiles\RansomwareResilience\Evidence\container-a-attack-output.json"

   if (-not (Test-Path $MimicScript)) { throw "Missing mimic script: $MimicScript" }
   if (-not (Test-Path $ContainerAEvidence)) { throw "Missing Container A positive-control evidence: $ContainerAEvidence" }
   ```

4. Discover the exact resource group from deployment tags. This avoids hard-coded resource-group names.

   ```powershell
   $TaggedGroups = @()
   $TaggedGroups += az group list --tag "deploymentId=$DID" --query "[].name" -o tsv
   $TaggedGroups += az group list --tag "DeploymentID=$DID" --query "[].name" -o tsv
   $TaggedGroups = @($TaggedGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

   if ($TaggedGroups.Count -eq 0) {
       $TaggedResources = @()
       $TaggedResources += az resource list --tag "deploymentId=$DID" --query "[].resourceGroup" -o tsv
       $TaggedResources += az resource list --tag "DeploymentID=$DID" --query "[].resourceGroup" -o tsv
       $TaggedGroups = @($TaggedResources | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
   }

   if ($TaggedGroups.Count -ne 1) {
       throw "Expected exactly one resource group for deployment id '$DID'; found: $($TaggedGroups -join ', ')"
   }

   $ResourceGroupName = $TaggedGroups[0]
   "Discovered resource group: $ResourceGroupName"
   ```

5. Discover the primary storage account by enumerating storage accounts in the exact resource group, excluding the dedicated restore staging account, and inspecting container names.

   ```powershell
   if ([string]::IsNullOrWhiteSpace($RestoreStagingStorageAccountName)) {
       throw "Restore staging storage account name is required for safe primary storage discovery."
   }

   $AllRgStorageAccounts = @(az storage account list -g $ResourceGroupName -o json | ConvertFrom-Json)
   $InspectedStorageAccounts = @()
   $StorageCandidates = @()

   foreach ($account in $AllRgStorageAccounts) {
       if ($account.name -eq $RestoreStagingStorageAccountName) {
           $InspectedStorageAccounts += [pscustomobject]@{
               Name = $account.name; ExcludedRestoreStage = $true; Containers = "excluded"; HasAllCanonical = $false; Id = $account.id
           }
           continue
       }

       $containerNames = @(az storage container list --account-name $account.name --auth-mode login --query "[].name" -o tsv)
       $containerNames = @($containerNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
       $hasAll = @(Compare-Object -ReferenceObject $RequiredContainers -DifferenceObject $containerNames -PassThru).Count -eq 0

       $record = [pscustomobject]@{
           Name = $account.name
           ExcludedRestoreStage = $false
           Containers = ($containerNames -join ", ")
           HasAllCanonical = $hasAll
           Id = $account.id
       }
       $InspectedStorageAccounts += $record
       if ($hasAll) { $StorageCandidates += $record }
   }

   $InspectedStorageAccounts | Sort-Object Name | Format-Table Name, ExcludedRestoreStage, HasAllCanonical, Containers -AutoSize
   $InspectedStorageAccounts | ConvertTo-Json -Depth 5 | Out-File "$EvidenceRoot\storage-discovery-inspection.json" -Encoding utf8

   if ($StorageCandidates.Count -ne 1) {
       throw "Expected exactly one non-staging primary storage account containing $($RequiredContainers -join ', '); found $($StorageCandidates.Count)."
   }

   $StorageAccountName = $StorageCandidates[0].Name
   $StorageId = $StorageCandidates[0].Id
   $BlobServiceId = "$StorageId/blobServices/default"

   "Primary lab/evidence storage account: $StorageAccountName"
   "Blob service diagnostic scope: $BlobServiceId"
   ```

6. Discover the single Log Analytics workspace and verify the Blob service diagnostic setting is attached at `/blobServices/default` scope.

   ```powershell
   $Workspaces = @(az monitor log-analytics workspace list -g $ResourceGroupName -o json | ConvertFrom-Json)
   if ($Workspaces.Count -ne 1) {
       throw "Expected exactly one Log Analytics workspace in '$ResourceGroupName'; found $($Workspaces.Count)."
   }

   $WorkspaceId = $Workspaces[0].customerId
   $WorkspaceName = $Workspaces[0].name

   $DiagnosticSettings = az monitor diagnostic-settings list --resource $BlobServiceId -o json | ConvertFrom-Json
   $DiagnosticSettings | ConvertTo-Json -Depth 10 | Out-File "$EvidenceRoot\blob-service-diagnostic-settings.json" -Encoding utf8

   if (-not ($DiagnosticSettings.value | Where-Object { $_.name -eq "blob-platform-logs" })) {
       throw "Expected diagnostic setting 'blob-platform-logs' at Blob service scope '$BlobServiceId'."
   }

   "Workspace: $WorkspaceName"
   "Diagnostic setting blob-platform-logs confirmed at Blob service scope."
   ```

7. Confirm Container B has a container-level immutability policy. Do not configure or depend on storage-account-level immutability.

   ```powershell
   $ContainerBPolicy = az storage container immutability-policy show `
     --account-name $StorageAccountName `
     --container-name $ContainerB `
     --auth-mode login `
     -o json | ConvertFrom-Json

   $ContainerBPolicy | ConvertTo-Json -Depth 10 | Out-File "$EvidenceRoot\container-b-immutability-policy.json" -Encoding utf8
   $ContainerBPolicy | Select-Object id, state, immutabilityPeriodSinceCreationInDays, allowProtectedAppendWrites | Format-List
   ```

> [!Important]
> The immutability caveat is part of the evidence. An unlocked time-based policy can be changed or removed by an authorized principal. Your conclusion should state that the policy blocked this overwrite/delete-style test, not that it is absolute protection against every authorized administrator.

## Task 2: Compare the positive control and run the mimic against Container B

In this task, you will confirm the deployment-time Container A counters, run the same parameterized mimic against Container B, and verify equal attempted-write counts.

1. Load and verify the Container A positive-control JSON.

   ```powershell
   $A = Get-Content $ContainerAEvidence -Raw | ConvertFrom-Json
   $A | Select-Object ContainerName, AttemptedWrites, SuccessfulWrites, FailedWrites | Format-List

   if ($A.ContainerName -ne $ContainerA) { throw "Container A evidence is for '$($A.ContainerName)', not '$ContainerA'." }
   if ([int]$A.AttemptedWrites -ne [int]$A.SuccessfulWrites -or [int]$A.FailedWrites -ne 0) {
       throw "Container A is not a valid positive control. Expected all attempted writes to succeed."
   }
   ```

2. Run the same mimic script against Container B.

   ```powershell
   $ContainerBRunOutput = "$EvidenceRoot\container-b-attack-output.json"

   & $MimicScript `
     -ResourceGroupName $ResourceGroupName `
     -StorageAccountName $StorageAccountName `
     -ContainerName $ContainerB `
     -OutputPath $ContainerBRunOutput

   $B = Get-Content $ContainerBRunOutput -Raw | ConvertFrom-Json
   $B | Select-Object ContainerName, AttemptedWrites, SuccessfulWrites, FailedWrites | Format-List

   if ($B.ContainerName -ne $ContainerB) { throw "Container B evidence is for '$($B.ContainerName)', not '$ContainerB'." }
   ```

3. Confirm the equal-attempt comparison and B rejection.

   ```powershell
   $CounterComparison = [pscustomobject]@{
       AContainer = $A.ContainerName
       AAttempted = [int]$A.AttemptedWrites
       ASuccessful = [int]$A.SuccessfulWrites
       AFailed = [int]$A.FailedWrites
       BContainer = $B.ContainerName
       BAttempted = [int]$B.AttemptedWrites
       BSuccessful = [int]$B.SuccessfulWrites
       BFailed = [int]$B.FailedWrites
       SameAttemptCount = ([int]$A.AttemptedWrites -eq [int]$B.AttemptedWrites)
       APositiveControl = ([int]$A.AttemptedWrites -eq [int]$A.SuccessfulWrites -and [int]$A.FailedWrites -eq 0)
       BRejectedAll = ([int]$B.SuccessfulWrites -eq 0 -and [int]$B.FailedWrites -eq [int]$B.AttemptedWrites)
   }

   $CounterComparison | Format-List

   if (-not $CounterComparison.SameAttemptCount) { throw "A and B attempted-write counts are not equal." }
   if (-not $CounterComparison.BRejectedAll) { throw "Container B did not reject all attempted writes." }
   ```

## Task 3: Build one compact evidence matrix

In this task, you will collect the three required evidence sources and write one matrix file at `$EvidenceRoot\challenge-04-evidence-matrix.md`. Do not create separate conclusion files.

1. Capture blob state and SHA-256 checksums for both containers. The hash comparison gives you data-state evidence in addition to the script counters.

   ```powershell
   function Get-ContainerStateWithHash {
       param(
           [Parameter(Mandatory=$true)][string]$AccountName,
           [Parameter(Mandatory=$true)][string]$ContainerName,
           [Parameter(Mandatory=$true)][string]$DownloadRoot
       )

       $containerDownloadRoot = Join-Path $DownloadRoot $ContainerName
       New-Item -ItemType Directory -Force -Path $containerDownloadRoot | Out-Null

       $blobs = @(az storage blob list `
         --account-name $AccountName `
         --container-name $ContainerName `
         --auth-mode login `
         --include metadata `
         -o json | ConvertFrom-Json)

       foreach ($blob in $blobs) {
           $safeName = ($blob.name -replace '[\\/:*?"<>|]', '_')
           $localPath = Join-Path $containerDownloadRoot $safeName
           az storage blob download `
             --account-name $AccountName `
             --container-name $ContainerName `
             --name $blob.name `
             --file $localPath `
             --auth-mode login `
             --overwrite true `
             --only-show-errors | Out-Null

           [pscustomobject]@{
               Container = $ContainerName
               Name = $blob.name
               Size = $blob.properties.contentLength
               LastModified = $blob.properties.lastModified
               ContentType = $blob.properties.contentSettings.contentType
               Metadata = ($blob.metadata | ConvertTo-Json -Compress)
               SHA256 = (Get-FileHash -Algorithm SHA256 -Path $localPath).Hash
           }
       }
   }

   $ChecksumRoot = "$EvidenceRoot\downloaded-blobs"
   $AState = @(Get-ContainerStateWithHash -AccountName $StorageAccountName -ContainerName $ContainerA -DownloadRoot $ChecksumRoot)
   $BState = @(Get-ContainerStateWithHash -AccountName $StorageAccountName -ContainerName $ContainerB -DownloadRoot $ChecksumRoot)

   $AStateByName = @{}
   foreach ($row in $AState) { $AStateByName[$row.Name] = $row }

   $StateComparison = foreach ($bBlob in $BState) {
       $aBlob = $AStateByName[$bBlob.Name]
       [pscustomobject]@{
           BlobName = $bBlob.Name
           A_Size = if ($aBlob) { $aBlob.Size } else { "missing-or-renamed" }
           B_Size = $bBlob.Size
           A_SHA256 = if ($aBlob) { $aBlob.SHA256 } else { "missing-or-renamed" }
           B_SHA256 = $bBlob.SHA256
           HashesMatch = if ($aBlob) { $aBlob.SHA256 -eq $bBlob.SHA256 } else { $false }
           A_LastModified = if ($aBlob) { $aBlob.LastModified } else { "missing-or-renamed" }
           B_LastModified = $bBlob.LastModified
       }
   }

   $StateComparison | Format-Table -AutoSize
   ```

2. Query Blob service logs once for both containers and both success/failure outcomes. This query uses the `StorageBlobLogs` table populated by the Blob service diagnostic setting.

   ```powershell
   $Kql = @"
   StorageBlobLogs
   | where TimeGenerated > ago(12h)
   | extend ContainerName = tostring(split(parse_url(Uri).Path, "/")[1])
   | where ContainerName in ("containera-unprotected", "containerb-protectme")
   | where OperationName in ("PutBlob", "PutBlock", "PutBlockList", "DeleteBlob", "SetBlobMetadata", "SetBlobProperties", "AppendBlock")
   | summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by ContainerName, OperationName, StatusCode, StatusText, AuthenticationType
   | order by ContainerName asc, LastSeen desc
   "@

   $PlatformLogSummaryRaw = az monitor log-analytics query `
     --workspace $WorkspaceId `
     --analytics-query $Kql `
     --timespan P1D `
     -o json

   $PlatformLogSummary = $PlatformLogSummaryRaw | ConvertFrom-Json
   $PlatformLogSummaryRaw | Out-File "$EvidenceRoot\platform-log-write-summary.json" -Encoding utf8
   $PlatformLogSummary.tables.rows | Format-Table -AutoSize
   ```

   > [!Note]
   > Storage resource logs are routed only after a diagnostic setting exists, and Log Analytics ingestion can lag. If the query is sparse, keep the diagnostic-setting evidence and the raw query output in the matrix, and state the ingestion limitation in the short conclusion.

3. Create the single compact evidence matrix and short conclusion.

   ```powershell
   $CounterJson = $CounterComparison | ConvertTo-Json -Compress
   $StateJson = $StateComparison | ConvertTo-Json -Depth 8 -Compress
   $DiagnosticsJson = $DiagnosticSettings | ConvertTo-Json -Depth 12 -Compress
   $PlatformRows = if ($PlatformLogSummary.tables.rows) { ($PlatformLogSummary.tables.rows | ConvertTo-Json -Depth 8 -Compress) } else { "[]" }

   $ShortConclusion = "The same benign mimic attempted $($CounterComparison.AAttempted) writes against both containers. The deployment-time positive control shows $($CounterComparison.ASuccessful) successful writes and 0 failures against containera-unprotected, while the Container B run shows 0 successful writes and $($CounterComparison.BFailed) failures against containerb-protectme. Blob state/checksum evidence and Blob service diagnostics/log query evidence support that Container B resisted equivalent tampering because of container-level immutability; if the policy is unlocked, an authorized principal can still modify or remove it, so this is tamper resistance for this scenario rather than absolute protection."

   $EvidenceMatrix = @"
   # Challenge 4 compact evidence matrix

   | Evidence source | Container A: containera-unprotected | Container B: containerb-protectme | Required interpretation |
   |---|---|---|---|
   | Deterministic discovery | Resource group `$ResourceGroupName`; primary storage `$StorageAccountName`; discovery inspected exact RG storage accounts, excluded restore staging `$RestoreStagingStorageAccountName`, and selected the account containing all canonical containers. | Same primary storage and Blob service diagnostic scope `$BlobServiceId`. | Primary storage discovery was deterministic and did not rely on prefix, sort order, or account-level immutability. |
   | Script output | Positive-control file `$ContainerAEvidence`; attempted `$($CounterComparison.AAttempted)`, succeeded `$($CounterComparison.ASuccessful)`, failed `$($CounterComparison.AFailed)`. | Run output `$ContainerBRunOutput`; attempted `$($CounterComparison.BAttempted)`, succeeded `$($CounterComparison.BSuccessful)`, failed `$($CounterComparison.BFailed)`. | SameAttemptCount=`$($CounterComparison.SameAttemptCount)`; APositiveControl=`$($CounterComparison.APositiveControl)`; BRejectedAll=`$($CounterComparison.BRejectedAll)`. Counter JSON: `$CounterJson` |
   | Blob state and checksum | Current blob state/checksums are included in comparison JSON. A is the attacked positive-control state. | Current blob state/checksums are included in comparison JSON. B retained protected data characteristics or rejected equivalent overwrite attempts. | State/checksum comparison JSON: `$StateJson` |
   | Blob service logs/diagnostics | `StorageBlobLogs` query summarizes recent successful/failure write operations for A when available. | `StorageBlobLogs` query summarizes recent failed/non-success write operations for B when available. | Diagnostic setting `blob-platform-logs` is attached at Blob service scope `/blobServices/default`. Diagnostic JSON: `$DiagnosticsJson`; platform rows: `$PlatformRows`; raw query file: `$EvidenceRoot\platform-log-write-summary.json` |
   | Canonical evidence upload | Not applicable. A evidence is deployment-time positive-control output. | B output must be uploaded to `lab-evidence/attacks/container-b/latest-attack-output.json`. | Validator 03 reads the uploaded B output from the evidence container. |

   ## Short conclusion

   $ShortConclusion
   "@

   $MatrixPath = "$EvidenceRoot\challenge-04-evidence-matrix.md"
   $EvidenceMatrix | Out-File $MatrixPath -Encoding utf8
   Get-Content $MatrixPath
   ```

## Task 4: Upload canonical B evidence and validate

In this task, you will upload the required Container B output JSON and run the validation. The canonical upload path is `lab-evidence/attacks/container-b/latest-attack-output.json`.

1. Upload the exact Container B output JSON to the evidence container.

   ```powershell
   az storage blob upload `
     --account-name $StorageAccountName `
     --container-name $EvidenceContainer `
     --name "attacks/container-b/latest-attack-output.json" `
     --file $ContainerBRunOutput `
     --overwrite true `
     --auth-mode login `
     -o json
   ```

2. Verify that the canonical evidence blob exists.

   ```powershell
   az storage blob show `
     --account-name $StorageAccountName `
     --container-name $EvidenceContainer `
     --name "attacks/container-b/latest-attack-output.json" `
     --auth-mode login `
     --query "{name:name, size:properties.contentLength, lastModified:properties.lastModified}" `
     -o table
   ```

3. Run the validation for this challenge. The inline validation invokes `Validations/03-task-tamper-attempt-evidence.ps1`, which checks the server-side evidence uploaded to `lab-evidence/attacks/container-b/latest-attack-output.json`.

   <validation step="Tamper attempt evidence captured"/>

## Summary

You ran the same benign encryption-mimic script against `containerb-protectme`, compared it to the deployment-time positive-control attack against `containera-unprotected`, and proved that A accepted the same number of attempted writes that B rejected. You kept the evidence compact by producing one matrix with script counters, blob state/checksum comparison, and Blob service logs/diagnostics, then uploaded the canonical B evidence for validation. You also preserved the immutability caveat: an unlocked container-level policy is tamper-resistant for this scenario, but an authorized principal can still modify or remove it.
