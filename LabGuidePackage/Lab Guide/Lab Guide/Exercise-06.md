# Challenge 6: Restore the VM, validate integrity, and produce a recovery runbook

### Estimated Duration: 55 minutes (includes VM restore wait)

## Scenario

You have investigated and contained the ransomware-style event. The final recovery challenge is to restore the protected Azure VM from the **single same-session recovery point** created for this lab, validate restored file integrity with SHA-256 checksums, protect the evidence marker in the primary lab/evidence storage account, clean up only restore-generated assets, and leave a concise recovery runbook that another operator could execute.

## Overview

In this challenge, you will use Azure Backup to restore the VM. The **55-minute budget includes mostly passive Azure restore processing**. A restore job that remains **InProgress** is **not** a failure while Azure Backup job details continue to show progress, updated subtasks, or other active job signals. While you wait, prepare the checksum command inputs and the concise runbook structure, but **do not execute checksum validation until the restore job is completed and the restored file system is accessible**.

You must keep the primary lab/evidence storage account separate from the dedicated restore staging account. The dedicated restore staging account for this lab is <inject key="restoreStagingStorageAccountName"></inject>.

## Objectives

- Task 1: Confirm the restore scope, staging account, and single recovery point.
- Task 2: Start the VM restore and monitor progress correctly.
- Task 3: Prepare validation inputs and a concise runbook while Azure restores.
- Task 4: Validate restored checksums only after restore completion and upload evidence.
- Task 5: Complete cleanup notes, concise runbook, and final validation.

## Task 1: Confirm the restore scope, staging account, and single recovery point

In this task, you will confirm the resources used for recovery and avoid selecting unsupported or inferred restore targets.

1. Sign in to the Azure portal at <https://portal.azure.com>.
   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
2. Confirm you are using subscription <inject key="SubscriptionID"></inject> in tenant <inject key="TenantID"></inject>.
3. Record the deployment identifier for this challenge: **deployment <inject key="DeploymentID" enableCopy="false"/>**.
4. Confirm the dedicated restore staging storage account name: <inject key="restoreStagingStorageAccountName"></inject>.
5. Locate the lab resource group by exact **deploymentId** or **DeploymentID** tag matching. If you use PowerShell, enter the deployment ID from the lab page when prompted.

   ```powershell
   $deploymentId = Read-Host 'Enter the exact deployment ID from the lab page'

   function Test-DeploymentTagMatch {
       param([hashtable]$Tags, [string]$DeploymentId)
       if (-not $Tags) { return $false }
       return (($Tags.ContainsKey('deploymentId') -and [string]$Tags['deploymentId'] -eq $DeploymentId) -or
               ($Tags.ContainsKey('DeploymentID') -and [string]$Tags['DeploymentID'] -eq $DeploymentId))
   }

   $candidateResourceGroups = @(Get-AzResourceGroup | Where-Object {
       Test-DeploymentTagMatch -Tags $_.Tags -DeploymentId $deploymentId
   })

   if ($candidateResourceGroups.Count -ne 1) {
       throw "Expected exactly one tagged lab resource group; found $($candidateResourceGroups.Count). Do not continue with inferred names."
   }

   $labResourceGroupName = $candidateResourceGroups[0].ResourceGroupName
   Get-AzResource -ResourceGroupName $labResourceGroupName |
       Select-Object Name, ResourceType, ResourceGroupName |
       Sort-Object ResourceType, Name
   ```

6. Identify and record these items:
   - **Operator VM for <inject key="DeploymentID" enableCopy="false"/>**: the Azure VM protected by Azure Backup.
   - **Recovery Services vault for <inject key="DeploymentID" enableCopy="false"/>**: the vault containing the VM backup item.
   - **Primary lab/evidence storage account for <inject key="DeploymentID" enableCopy="false"/>**: the storage account that contains **containera-unprotected**, **containerb-protectme**, and **lab-evidence**.
   - **Dedicated restore staging storage account for <inject key="DeploymentID" enableCopy="false"/>**: <inject key="restoreStagingStorageAccountName"></inject>.
7. Prove the two storage accounts are distinct:
   - The primary account contains **containera-unprotected**, **containerb-protectme**, and **lab-evidence**.
   - The dedicated staging account name exactly matches <inject key="restoreStagingStorageAccountName"></inject>.
   - The primary account and staging account names are not the same.
8. Open the VM backup item from either supported route:
   - **Recovery Services vault** > the protected Azure VM backup item > **Restore VM**.
   - **Resiliency** > **Recover** > set **Datasource type** to **Azure Virtual machines** > select the protected VM.
9. Confirm that the restore source is the **single same-session recovery point** created during this lab. Record its timestamp and recovery point type. Do not describe or select a multi-day recovery history; this lab intentionally provides one recovery point.

> [!Important]
> Never delete the primary lab/evidence storage account, **containera-unprotected**, **containerb-protectme**, or anything under **lab-evidence**. Those resources hold prior challenge evidence and final validation markers.

## Task 2: Start the VM restore and monitor progress correctly

In this task, you will start the restore and monitor Azure Backup job state. The elapsed time in this task is expected and is included in the 55-minute challenge budget.

1. Start the restore from the VM backup item.
2. Select the single same-session recovery point recorded in Task 1.
3. Choose a recovery option that preserves the original VM until validation passes:
   - Prefer **Create new virtual machine** when the portal allows direct alternate-location restore.
   - Use **Restore disks** if you need to inspect or create from restored disks.
   - Avoid replacing the original VM before checksum validation succeeds.
4. If the restore option asks for a staging location, select the dedicated restore staging storage account whose exact name is <inject key="restoreStagingStorageAccountName"></inject>.
5. Do **not** use the primary lab/evidence storage account for restore staging. Restore-generated VHDs, templates, temporary containers, or similar artifacts must stay outside the evidence account.
6. Start the restore job and record:
   - Restore job name or job ID.
   - Start time.
   - Selected recovery point timestamp.
   - Restore option used.
   - Target restored VM name or restored disk names.
   - Dedicated staging account used, if applicable.
7. Monitor the job from **Recovery Services vault** > **Backup Jobs** or the current **Resiliency** jobs view.
8. Treat **InProgress** correctly:
   - **InProgress is not failure** while job details continue to update, subtasks advance, percentage complete changes, bytes transferred changes, or Azure reports ongoing work.
   - Continue monitoring active progress instead of using a conflicting fixed wait time.
   - Escalate only if Azure reports a clear failure, a blocking validation error, or no meaningful progress according to your lab-support process.

> [!Tip]
> Azure Backup restore operations can take meaningful time even for a small lab VM. Microsoft Learn documents restore jobs that report **InProgress** and recommends tracking job details. The 55-minute estimate for this challenge already includes the mostly passive restore wait.

## Task 3: Prepare validation inputs and a concise runbook while Azure restores

In this task, you will use the passive restore time productively without running integrity checks too early.

1. While the restore job is **InProgress**, prepare the checksum command inputs in your notes:
   - Manifest path after restore: **C:\LabFiles\RansomwareResilience\Evidence\checksum-reference.json**.
   - Seed data root after restore: **C:\LabFiles\RansomwareResilience\SeedData**.
   - Local result file to create after validation: **C:\LabFiles\RansomwareResilience\Evidence\restore-checksum-complete.json**.
   - Evidence upload destination after validation: **lab-evidence/challenge-06/restore-checksum-complete.json** in the **primary lab/evidence storage account**, not the staging account.
2. Prepare, but do not yet complete, this concise runbook structure:

   ```text
   # Recovery Runbook - Challenge 6

   1. Scope
      - Restore Azure VM from the single same-session recovery point.
      - No multi-day recovery-point selection is assumed.

   2. Governance and approval boundary
      - Vault and Resource Guard association:
      - Protected operation observed in Challenge 3:
      - Why this lab did not perform full approval:
      - Production model: separate approver, eligible Backup MUA Operator, approval-controlled time-bound PIM activation, no standing guard authority for vault admin.

   3. Restore record
      - Subscription / tenant / deployment:
      - Resource group:
      - Recovery Services vault:
      - Source VM:
      - Recovery point timestamp:
      - Restore option:
      - Restore job ID:
      - Target restored VM or disks:
      - Dedicated staging account:

   4. Monitoring and timing
      - Job status history:
      - Progress signals used:
      - Failure or escalation trigger:

   5. Integrity validation
      - Manifest path:
      - Seed data root:
      - Result JSON path:
      - Files passed:
      - Files failed:
      - Return-to-service decision:

   6. Rollback and cleanup
      - Original VM kept unchanged until validation:
      - If validation fails:
      - If validation passes:
      - Restore-generated resources to remove:
      - Evidence and primary containers to retain:

   7. Lessons learned
      - Backup governance:
      - MUA / Resource Guard scope:
      - Immutability limitation:
      - Investigation and key rotation:
      - Restore validation:
   ```

3. Do not execute the checksum command while the restore job is still **InProgress**. You may only prepare paths, notes, and the empty runbook template during the wait.
4. When the restore job changes to **Completed**, open the restored VM or attach/mount the restored disks according to the restore option you selected.

> [!Important]
> Checksum validation must run against the restored file system. Running the command on the original VM before restore completion does not prove recovery integrity and does not satisfy this challenge.

## Task 4: Validate restored checksums only after restore completion and upload evidence

In this task, you will run the checksum comparison after Azure Backup reports the restore job as completed and the restored file system is accessible.

1. Confirm all prerequisites before running the checksum command:
   - Restore job status is **Completed**.
   - The restored VM or restored disks are accessible.
   - You are reading the restored copy of **C:\LabFiles\RansomwareResilience\Evidence\checksum-reference.json**.
   - You are hashing files under the restored copy of **C:\LabFiles\RansomwareResilience\SeedData**.
2. On the restored VM, or on a helper VM where the restored disk is mounted at the original drive letter, open an elevated PowerShell session and run the checksum comparison.

   ```powershell
   $manifestPath = 'C:\LabFiles\RansomwareResilience\Evidence\checksum-reference.json'
   $seedRoot = 'C:\LabFiles\RansomwareResilience\SeedData'
   $resultPath = 'C:\LabFiles\RansomwareResilience\Evidence\restore-checksum-complete.json'

   if (-not (Test-Path -LiteralPath $manifestPath)) {
       throw "Checksum manifest not found: $manifestPath"
   }
   if (-not (Test-Path -LiteralPath $seedRoot)) {
       throw "Seed data folder not found: $seedRoot"
   }

   $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

   if ($manifest -is [System.Array]) {
       $entries = $manifest
   }
   elseif ($manifest.files) {
       $entries = $manifest.files
   }
   else {
       $entries = $manifest.PSObject.Properties | ForEach-Object {
           [pscustomobject]@{ Path = $_.Name; SHA256 = [string]$_.Value }
       }
   }

   $results = foreach ($entry in $entries) {
       $relativePath = $entry.BlobName
       if (-not $relativePath) { $relativePath = $entry.relativePath }
       if (-not $relativePath) { $relativePath = $entry.path }
       if (-not $relativePath) { $relativePath = $entry.file }
       if (-not $relativePath) { $relativePath = $entry.name }

       $expectedHash = $entry.SHA256
       if (-not $expectedHash) { $expectedHash = $entry.sha256 }
       if (-not $expectedHash) { $expectedHash = $entry.hash }

       if (-not $relativePath -or -not $expectedHash) {
           [pscustomobject]@{
               File         = 'MANIFEST_ENTRY_MISSING_PATH_OR_HASH'
               ExpectedHash = [string]$expectedHash
               ActualHash   = $null
               Result       = 'Failed'
               Reason       = 'Manifest entry did not contain a recognizable path and SHA-256 hash.'
           }
           continue
       }

       $relativePath = ([string]$relativePath).Replace('/', '\')
       $filePath = Join-Path -Path $seedRoot -ChildPath $relativePath

       if (-not (Test-Path -LiteralPath $filePath)) {
           [pscustomobject]@{
               File         = $relativePath
               ExpectedHash = $expectedHash.ToUpperInvariant()
               ActualHash   = $null
               Result       = 'Failed'
               Reason       = 'File missing from restored SeedData folder.'
           }
           continue
       }

       $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
       [pscustomobject]@{
           File         = $relativePath
           ExpectedHash = $expectedHash.ToUpperInvariant()
           ActualHash   = $actualHash.ToUpperInvariant()
           Result       = if ($actualHash -ieq $expectedHash) { 'Passed' } else { 'Failed' }
           Reason       = if ($actualHash -ieq $expectedHash) { 'SHA-256 match.' } else { 'SHA-256 mismatch.' }
       }
   }

   $passed = @($results | Where-Object Result -eq 'Passed').Count
   $failed = @($results | Where-Object Result -ne 'Passed').Count

   $summary = [pscustomobject]@{
       challenge        = 'Challenge 6'
       validation       = 'Restore checksum comparison'
       status           = if ($failed -eq 0 -and $passed -gt 0) { 'Succeeded' } else { 'Failed' }
       checkedAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
       manifestPath     = $manifestPath
       seedRoot         = $seedRoot
       filesPassed      = $passed
       filesFailed      = $failed
       results          = $results
   }

   $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
   $summary | Format-List challenge,validation,status,checkedAtUtc,manifestPath,seedRoot,filesPassed,filesFailed
   $results | Format-Table File,Result,Reason -AutoSize

   if ($summary.status -ne 'Succeeded') {
       throw "Restore checksum comparison failed for $failed file(s). Review $resultPath."
   }
   ```

3. Preserve the exact checksum evidence schema created by the command. The top-level JSON object must contain these properties:

   ```json
   {
     "challenge": "Challenge 6",
     "validation": "Restore checksum comparison",
     "status": "Succeeded or Failed",
     "checkedAtUtc": "ISO 8601 UTC timestamp",
     "manifestPath": "C:\\LabFiles\\RansomwareResilience\\Evidence\\checksum-reference.json",
     "seedRoot": "C:\\LabFiles\\RansomwareResilience\\SeedData",
     "filesPassed": 0,
     "filesFailed": 0,
     "results": [
       {
         "File": "relative file path",
         "ExpectedHash": "expected SHA-256",
         "ActualHash": "actual SHA-256 or null",
         "Result": "Passed or Failed",
         "Reason": "validation explanation"
       }
     ]
   }
   ```

4. Confirm return-to-service readiness only when:
   - Restore job is **Completed**.
   - Restored VM or restored disks are accessible.
   - Every manifest entry passes SHA-256 comparison.
   - No unexpected encryption-mimic output is present in the restored file set.
   - Any production replacement decision includes access-control and monitoring reapplication.
5. Upload **C:\LabFiles\RansomwareResilience\Evidence\restore-checksum-complete.json** to the primary lab/evidence storage account as **lab-evidence/challenge-06/restore-checksum-complete.json**. Do not upload the marker to the dedicated staging account.
6. If you use PowerShell for upload, use Microsoft Entra authorization and the primary account name you identified in Task 1.

   ```powershell
   $primaryStorageAccountName = Read-Host 'Enter the primary lab/evidence storage account name, not the staging account'
   $resultPath = 'C:\LabFiles\RansomwareResilience\Evidence\restore-checksum-complete.json'

   if (-not (Test-Path -LiteralPath $resultPath)) {
       throw "Result file not found: $resultPath"
   }

   $ctx = New-AzStorageContext -StorageAccountName $primaryStorageAccountName -UseConnectedAccount
   Set-AzStorageBlobContent `
       -File $resultPath `
       -Container 'lab-evidence' `
       -Blob 'challenge-06/restore-checksum-complete.json' `
       -Context $ctx `
       -Force
   ```

> [!Important]
> The evidence marker must be nonsecret. Do not include passwords, storage keys, SAS tokens, connection strings, private keys, or file contents in the uploaded JSON.

## Task 5: Complete cleanup notes, concise runbook, and final validation

In this task, you will complete a concise recovery runbook and document cleanup of restore-generated resources.

1. Finish **Recovery-Runbook-<inject key="DeploymentID" enableCopy="false"/>.md** using the concise structure from Task 3. Keep it short: record exact names, timestamps, job signals, validation counts, and decisions rather than long narrative paragraphs.
2. Ensure the runbook includes these required statements:
   - The restore used the **single same-session recovery point** available in this lab.
   - The dedicated restore staging account was <inject key="restoreStagingStorageAccountName"></inject> and was distinct from the primary lab/evidence storage account.
   - The 55-minute challenge budget included mostly passive Azure restore processing.
   - **InProgress** was treated as normal while job progress continued.
   - Checksum validation was not executed until after restore completion.
   - The checksum evidence followed the required schema and was uploaded to **lab-evidence/challenge-06/restore-checksum-complete.json** in the primary lab/evidence storage account.
   - Resource Guard-backed MUA protects selected destructive or high-impact Azure Backup actions, not all administration.
   - A production MUA model requires a separate approver, eligible **Backup MUA Operator** assignment, approval-controlled and time-bound PIM activation, and no standing guard authority for the vault administrator.
   - This lab did not perform full approval because only one Microsoft Entra learner identity is supplied.
3. Document cleanup using this minimum table. Do not delete anything until ownership is verified.

   | Candidate cleanup item | Resource type | Name | Restore job relationship | Keep or remove | Reason |
   | --- | --- | --- | --- | --- | --- |
   | Restored VM, if temporary | Azure VM |  |  |  |  |
   | Restore-generated managed disks | Managed disks |  |  |  |  |
   | Restore-generated NICs or public IPs | Network resources |  |  |  |  |
   | Restore-generated staging blobs, VHDs, templates, or containers | Blob storage artifacts in dedicated staging account |  |  |  |  |
   | Primary lab evidence | lab-evidence container | challenge-06/restore-checksum-complete.json | Final evidence | Keep | Required for validation |

4. Cleanup rules:
   - Remove only resources confirmed to be created by the restore test and not retained as the replacement VM.
   - Do not delete the original VM as part of normal challenge cleanup.
   - Do not delete the dedicated restore staging storage account itself unless full lab teardown is explicitly authorized; remove only unneeded restore-generated contents inside it.
   - Do not delete the primary lab/evidence storage account, **containera-unprotected**, **containerb-protectme**, or anything under **lab-evidence**.
   - Do not delete the Recovery Services vault or Resource Guard during this challenge.
5. Run the final validation. This validation checks the recovery and investigation evidence, including the Challenge 6 checksum marker.

<validation step="Recovery and investigation completion"/>

## Summary

You restored the VM from the lab's single same-session recovery point, used the dedicated staging account when staging was required, monitored Azure Backup progress without treating an actively progressing **InProgress** job as failure, prepared validation and runbook materials during the passive wait, executed checksum validation only after restore completion, uploaded the exact-schema checksum evidence to the primary lab/evidence account, documented cleanup without damaging protected evidence, and completed the final validation.
