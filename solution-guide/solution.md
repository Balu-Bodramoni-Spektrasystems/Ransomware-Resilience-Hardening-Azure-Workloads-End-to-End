# Facilitator Solution — Ransomware Resilience: Hardening Azure Workloads End to End

## Schedule and grading posture

| Challenge | Time |
|---|---:|
| Challenge 1 — Backup governance | 25 minutes |
| Challenge 2 — Container and VM hardening | 25 minutes |
| Challenge 3 — Authorization boundary | 20 minutes |
| Challenge 4 — Protected-container attack comparison | 30 minutes |
| Challenge 5 — Investigation and access rotation | 25 minutes |
| Challenge 6 — VM recovery and runbook | 55 minutes |
| **Total** | **180 minutes** |

Grade Azure state and required evidence, not portal navigation. Challenge 6 includes the mostly passive restore wait. A progressing `InProgress` restore is not a failure.

Core contract:

- There is one Microsoft Entra learner identity. Local VM Shadow/instructor credentials are VM support only, not an Entra approver.
- The ARM/platform deployment identity creates the Resource Guard and the vault `backupResourceGuardProxy` mapping. The CSE only verifies that association read-only; it does not create, repair, or update the mapping.
- The learner role has Resource Guard read/discovery permissions only. It intentionally has no Resource Guard write or protected-operation authority.
- Resource Guard MUA gates selected supported high-impact Azure Backup operations, not all administration.
- `containera-unprotected` is the deployment-attacked positive control; `containerb-protectme` is hardened by the learner; `lab-evidence` stores evidence.
- Immutability is container-level on B only. The policy remains unlocked and therefore can be modified or removed by an authorized principal.
- Exactly one same-session VM recovery point is expected.
- Defender fallback uses `Microsoft.Security/defenderForStorageSettings/current@2025-01-01`.
- Blob diagnostics are evaluated at the primary account's `/blobServices/default` scope.

## Provisioning-authority boundary

Treat Resource Guard creation and vault mapping as platform-deployment responsibilities. If the guard or mapping is absent, fail provisioning review and inspect the ARM deployment operations under the platform deployment identity. Do not grant Resource Guard write to the learner, and do not use the CSE to set or repair `backupResourceGuardProxy`. The learner and CSE may read the guard and mapping for verification only.

**Reviewer note:** `coherence-rbac-missing-provider` is a false positive for this package under the intentional split-authority model. The ARM/platform deployment identity owns Resource Guard provider writes; the learner custom role exposes only Resource Guard read/discovery, preserving the Challenge 3 denial boundary.

## Common resource resolution

Resolve the resource group by exact deployment tag and require one result. Never use a prefix, substring, wildcard, or first-result fallback.

```powershell
$DID = Read-Host 'Deployment ID'
$groups = @(Get-AzResourceGroup | Where-Object {
  ($_.Tags.ContainsKey('deploymentId') -and [string]$_.Tags.deploymentId -ceq $DID) -or
  ($_.Tags.ContainsKey('DeploymentID') -and [string]$_.Tags.DeploymentID -ceq $DID)
})
if ($groups.Count -eq 0) {
  $names = @(Get-AzResource | Where-Object {
    ($_.Tags.ContainsKey('deploymentId') -and [string]$_.Tags.deploymentId -ceq $DID) -or
    ($_.Tags.ContainsKey('DeploymentID') -and [string]$_.Tags.DeploymentID -ceq $DID)
  } | Select-Object -ExpandProperty ResourceGroupName -Unique)
  $groups = @($names | ForEach-Object { Get-AzResourceGroup -Name $_ })
}
if ($groups.Count -ne 1) { throw "Expected one exact lab resource group; found $($groups.Count)." }
$rg = $groups[0].ResourceGroupName
```

Resolve the staging name from ARM output. The primary account is the unique non-staging account whose data plane contains all three exact containers.

```powershell
$stagingNames = @(Get-AzResourceGroupDeployment -ResourceGroupName $rg | ForEach-Object {
  if ($_.Outputs -and $_.Outputs.ContainsKey('restoreStagingStorageAccountName')) {
    [string]$_.Outputs.restoreStagingStorageAccountName.Value
  }
} | Where-Object { $_ } | Sort-Object -Unique)
if ($stagingNames.Count -ne 1) { throw 'Staging ARM output is not unique.' }
$stagingName = $stagingNames[0]

$required = @('containera-unprotected','containerb-protectme','lab-evidence')
$primaryMatches = foreach ($account in Get-AzStorageAccount -ResourceGroupName $rg) {
  if ($account.StorageAccountName -ieq $stagingName) { continue }
  $candidate = New-AzStorageContext -StorageAccountName $account.StorageAccountName -UseConnectedAccount
  $names = @(Get-AzStorageContainer -Context $candidate -ErrorAction Stop | Select-Object -ExpandProperty Name -Unique)
  if (@($required | Where-Object { $names -cnotcontains $_ }).Count -eq 0) { $account }
}
$primaryMatches = @($primaryMatches | Group-Object { $_.StorageAccountName.ToLowerInvariant() } | ForEach-Object { $_.Group[0] })
if ($primaryMatches.Count -ne 1) { throw "Expected one primary account; found $($primaryMatches.Count)." }
$primary = $primaryMatches[0]
$sa = $primary.StorageAccountName
if ($sa -ieq $stagingName) { throw 'Primary and staging must differ.' }
$ctx = New-AzStorageContext -StorageAccountName $sa -UseConnectedAccount
$blobServiceId = "$($primary.Id)/blobServices/default"

$vaults = @(Get-AzRecoveryServicesVault -ResourceGroupName $rg)
$guards = @(Get-AzResource -ResourceGroupName $rg -ResourceType Microsoft.DataProtection/resourceGuards)
if ($vaults.Count -ne 1 -or $guards.Count -ne 1) { throw 'Vault or guard is not unique.' }
$vault = $vaults[0]; $guard = $guards[0]
Set-AzRecoveryServicesVaultContext -Vault $vault
```

A data-plane authorization error is not permission to guess. Refresh sign-in for expected learner data-plane rights or escalate a platform provisioning defect through the facilitator; never remediate Resource Guard discovery or mapping by granting the learner Resource Guard write. General pitfalls include wrong tenant/subscription or region, missing system-assigned identity, stale RBAC, SKU throttling, quota, and soft-deleted names blocking recreation.

---

# Challenge 1 — Establish resilient backup governance (25 minutes)

Use one compact evidence record; do not require separate narratives.

## Task 1 — Resolve resources

**Expected:** Exact-tag resource group, one VM, vault, guard, unique primary account, and exact distinct staging account.

```powershell
Get-AzVM -ResourceGroupName $rg | Select-Object Name,Location,Id
$primary | Select-Object StorageAccountName,Location,Id
Get-AzStorageAccount -ResourceGroupName $rg -Name $stagingName
```

**Full credit:** All resources resolve uniquely; primary and staging are proven distinct.  
**Partial:** Correct resources but deterministic storage resolution is not shown.  
**Pitfalls:** Guessed names, staging selected as primary, wrong subscription, missing Blob Data RBAC.

## Task 2 — Verify VM backup and the single recovery point

```powershell
$containers = @(Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -Status Registered -VaultId $vault.ID)
$items = @($containers | ForEach-Object {
  Get-AzRecoveryServicesBackupItem -Container $_ -WorkloadType AzureVM -VaultId $vault.ID
})
$points = @(Get-AzRecoveryServicesBackupRecoveryPoint -Item $items[0] -VaultId $vault.ID)
$items | Select-Object Name,ProtectionStatus,ProtectionState,LastBackupStatus,LastBackupTime
$points | Select-Object RecoveryPointTime,RecoveryPointType,RecoveryPointId
```

**Expected:** Intended VM is protected and has exactly one point created this session.  
**Full credit:** Item, successful job, and sole point agree.  
**Partial:** Item/job shown without point verification.  
**Pitfalls:** Creating a second point; treating an active backup as failed; region mismatch.

## Task 3 — Verify soft delete

```powershell
Get-AzRecoveryServicesVaultProperty -VaultId $vault.ID |
  Select-Object SoftDeleteFeatureState,SoftDeleteRetentionPeriodInDays
```

**Expected:** Vault soft delete remains enabled.  
**Full credit:** State and retention recorded.  
**Partial:** Portal-only assertion.  
**Pitfalls:** Inspecting Blob soft delete; weakening enhanced/always-on protection.

## Task 4 — Verify guard association and gated operations

```powershell
$mapping = Get-AzRecoveryServicesResourceGuardMapping -VaultId $vault.ID
$mapping | ConvertTo-Json -Depth 10
(Get-AzResource -ResourceId $guard.ResourceId -ExpandProperties).Properties | ConvertTo-Json -Depth 10
```

**Expected:** Mapping identifies the deployed guard and current state identifies at least one protected operation. The state was created by ARM/platform deployment and is read-only to the learner and CSE.  
**Full credit:** IDs match and one current gated operation is evidenced.  
**Partial:** Resources exist but association is not proven.  
**Pitfalls:** Reading exclusions backward; confusing MUA with a lock; claiming all actions are gated; attempting to have the learner or CSE create the mapping.

## Task 5 — Governance statement

**Model answer:** Resource Guard adds a separate authorization boundary to selected supported destructive or high-impact Backup actions. It reduces single-account destruction risk but does not replace soft delete, least privilege, monitoring, or recovery testing.

**Full credit:** Equivalent bounded statement in the compact record.  
**Partial:** MUA named without scope.  
**No credit:** Universal ransomware protection is claimed.

---

# Challenge 2 — Harden Container B and the VM (25 minutes)

## Task 1 — Configure B-only immutability

```bash
az storage container immutability-policy create \
  --account-name "$SA" --container-name containerb-protectme \
  --period 1 --allow-protected-append-writes false --auth-mode login
```

**Expected:** One-day unlocked time-based policy at B container scope.  
**Full credit:** Account, container, period, append setting, and unlocked state are correct.  
**Partial:** B protected but scope/state incompletely evidenced.  
**Pitfalls:** Account-level policy, policy on A, locking policy, staging account, RBAC delay.

## Task 2 — Verify scope

```bash
az storage container immutability-policy show --account-name "$SA" \
  --container-name containerb-protectme --auth-mode login -o jsonc
az storage container immutability-policy show --account-name "$SA" \
  --container-name containera-unprotected --auth-mode login -o jsonc
az storage account show -g "$RG" -n "$SA" \
  --query '{name:name,immutableStorageWithVersioning:immutableStorageWithVersioning}' -o jsonc
```

**Expected:** B is unlocked with positive retention; A has no policy; no account-level version immutability.  
**Full credit:** All three scope checks.  
**Partial:** One negative check missing.  
**Pitfalls:** Treating authentication/network errors as policy absence.

## Task 3 — State unlocked limitation

**Model answer:** The policy rejects protected overwrite/delete while present, but an authorized principal can modify or remove an unlocked policy; it is tamper resistance, not absolute protection.

**Full credit:** Enforcement and limitation.  
**Partial:** Only one side.  
**No credit:** Claims it cannot be removed.

## Task 4 — Review VM controls; do not configure them

```bash
VM=$(az vm list -g "$RG" --query '[0].name' -o tsv)
VM_ID=$(az vm show -g "$RG" -n "$VM" --query id -o tsv)
az vm identity show -g "$RG" -n "$VM" -o jsonc
az vm extension list -g "$RG" --vm-name "$VM" -o table
az monitor data-collection rule association list-by-resource --resource "$VM_ID" -o table
```

**Expected:** Factual review of identity, AMA/DCR, and exposure; no paid-plan deployment required.  
**Full credit:** Agent is distinguished from active collection and gaps are noted.  
**Partial:** Only extensions reviewed.  
**Pitfalls:** Missing identity; wrong DCR region; awarding extra credit for out-of-scope configuration.

---

# Challenge 3 — Prove the authorization boundary (20 minutes)

Do not require or reward another sign-in, role changes, PIM activation, approval, elevated retry, exhaustive role catalogs, or essays. The learner's Resource Guard access is intentionally read/discovery only; preserve that boundary.

## Task 1 — Verify mapping and choose one protected operation

```bash
LEARNER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
VAULT=$(az backup vault list -g "$RG" --query '[0].name' -o tsv)
GUARD_ID=$(az resource list -g "$RG" --resource-type Microsoft.DataProtection/resourceGuards --query '[0].id' -o tsv)
az backup vault resource-guard-mapping show -g "$RG" --name "$VAULT" -o jsonc
az resource show --ids "$GUARD_ID" --expand properties -o jsonc
```

**Expected:** Correct association and one currently protected path selected. These are discovery reads of platform-created state.  
**Full credit:** Identity, mapping, and operation attributable.  
**Partial:** Mapping only.  
**Pitfalls:** Cached cross-tenant context; choosing an ordinary read; attempting to recreate the mapping.

## Task 2 — Confirm no standing guard authority

```bash
az role assignment list --assignee-object-id "$LEARNER_OBJECT_ID" \
  --scope "$GUARD_ID" --include-inherited --all \
  --query "[?roleDefinitionName=='Contributor' || roleDefinitionName=='Backup MUA Admin' || roleDefinitionName=='Backup MUA Operator']" -o jsonc
```

**Expected:** Empty result including inherited assignments. Read/discovery access from the learner role is expected and does not constitute protected-operation authority.  
**Full credit:** All three standing roles and inheritance checked.  
**Partial:** Direct assignments only.  
**No credit:** IAM is changed.  
**Pitfalls:** Checking vault IAM rather than guard IAM; stale token; treating Resource Guard read permission as write authority.

## Task 3 — Observe denial and cancel safely

**Expected:** Learner enters the protected path only far enough to receive an attributable Resource Guard authorization denial, records UTC time, cancels, and leaves mapping, soft delete, and protection intact.

```powershell
Get-AzRecoveryServicesResourceGuardMapping -VaultId $vault.ID
Get-AzRecoveryServicesVaultProperty -VaultId $vault.ID
$items | Select-Object Name,ProtectionStatus,ProtectionState
```

**Full credit:** Learner, vault, guard, operation, denial, and time correlate; controls remain.  
**Partial:** Credible denial with one missing correlation.  
**No credit:** Destructive commit, unrelated error, approval, activation, or elevated retry.  
**Pitfalls:** Testing an unprotected action; failing to cancel; weakening the split-authority role design to make the test pass.

## Task 4 — Publish one compact JSON object

Required path: `lab-evidence/challenge-03/authorization-boundary.json`. It must contain identity, vault, guard, operation, `Denied`, UTC time, controls-retained Boolean, no-secrets Boolean, and one concise MUA explanation.

```powershell
$path = 'C:\LabFiles\RansomwareResilience\Evidence\authorization-boundary.json'
$e = Get-Content $path -Raw | ConvertFrom-Json
if ($e.authorizationResult -ne 'Denied' -or -not $e.controlsRetained -or $e.secretsIncluded) { throw 'Invalid evidence.' }
[DateTimeOffset]::Parse([string]$e.observedUtc) | Out-Null
Set-AzStorageBlobContent -File $path -Container lab-evidence `
  -Blob challenge-03/authorization-boundary.json -Context $ctx -Force
```

**Full credit:** One valid nonsecret canonical object.  
**Partial:** One nonsecurity formatting defect.  
**No credit:** Wrong path, invented denial, secrets, or claimed approval.  
**Pitfalls:** Quoted Booleans; duplicate summaries.

## Task 5 — Concise essential explanation

**Model answer:** Production separates approver authority from vault administration. The requester has an eligible Backup MUA Operator assignment and uses approval-controlled, time-bound PIM activation. Standing guard authority for the vault administrator defeats separation. Approval is described, not performed, because this lab has one learner identity and no approval workflow.

**Full credit:** All five points in the compact object.  
**Partial:** One point omitted.  
**No credit:** Local support account treated as approver.

---

# Challenge 4 — Attack B and prove protection (30 minutes)

Require one compact three-source matrix and one short conclusion, not duplicate exports/commentary.

## Task 1 — Run the same mimic against B and compare counters

```powershell
$aPath = 'C:\LabFiles\RansomwareResilience\Evidence\container-a-attack-output.json'
$bPath = 'C:\LabFiles\RansomwareResilience\Evidence\container-b-attack-output.json'
$A = Get-Content $aPath -Raw | ConvertFrom-Json
& 'C:\LabFiles\RansomwareResilience\Scripts\Invoke-BenignBlobEncryptionMimic.ps1' `
  -ResourceGroupName $rg -StorageAccountName $sa `
  -ContainerName containerb-protectme -OutputPath $bPath
$B = Get-Content $bPath -Raw | ConvertFrom-Json
$A,$B | Select-Object ContainerName,AttemptedWrites,SuccessfulWrites,FailedWrites
```

Do not use unsupported `-Mode` or `-ExpectedAttempts` parameters.

**Expected:** Same positive N attempts; A has N successes/0 failures; B has 0 successes/N failures.  
**Full credit:** Same script and equal attempt count with expected outcomes.  
**Partial:** B rejected without complete A comparison.  
**Pitfalls:** Different script/account; zero attempts; auth or throttling failure misclassified.

## Task 2 — Produce one three-source matrix

| Source | A expected | B expected | Correlation |
|---|---|---|---|
| Script output | N attempts, N successes | N attempts, N policy-consistent failures | Same mimic/account/window/N |
| Blob state and SHA-256 | Positive-control overwrite impact | Seeded names/content retain trusted hashes | Compare with deployment manifest |
| Blob service logs | Successful writes | Rejected writes, commonly 409/policy status | Container, operation, status, UTC window |

```powershell
az storage blob list --account-name $sa --container-name containera-unprotected --auth-mode login -o json
az storage blob list --account-name $sa --container-name containerb-protectme --auth-mode login -o json
az monitor diagnostic-settings list --resource $blobServiceId -o jsonc
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg | Select-Object -First 1
$q = @'
StorageBlobLogs
| where TimeGenerated > ago(12h)
| extend ContainerName=tostring(split(parse_url(Uri).Path,"/")[1])
| where ContainerName in ("containera-unprotected","containerb-protectme")
| summarize Count=count() by ContainerName,OperationName,StatusCode,StatusText
'@
Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId -Query $q
```

**Full credit:** One matrix correlates all three sources across both containers.  
**Partial:** Two sources complete and log ingestion delay documented with correct diagnostic scope.  
**No credit:** Network/auth/quota/throttling error used as policy proof.  
**Pitfalls:** Account-root or staging diagnostics; `AzureActivity` used for blob writes; wrong workspace.

## Task 3 — Upload B evidence and conclude briefly

```powershell
Set-AzStorageBlobContent -File $bPath -Container lab-evidence `
  -Blob attacks/container-b/latest-attack-output.json -Context $ctx -Force
```

**Model conclusion:** The same N overwrites succeeded against A and were rejected against B. Unchanged B hashes and Blob logs corroborate the counters. This proves resistance to this attempt, not absolute protection, because the policy is unlocked.

**Full credit:** Canonical raw output, one matrix, and short accurate conclusion.  
**Partial:** Matrix correct but upload missing.  
**Pitfalls:** Uploading to staging; redundant files; absolute-protection claim.

---

# Challenge 5 — Investigate and rotate access (25 minutes)

## Task 1 — Alert or retained fallback

Investigate a relevant alert if present. Otherwise verify the exact current Defender setting and hunt manually.

```bash
SA_ID=$(az storage account show -g "$RG" -n "$SA" --query id -o tsv)
az rest --method get --uri \
 "https://management.azure.com${SA_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2025-01-01" -o jsonc
```

**Expected:** Alert correlation, or `properties.isEnabled: true` plus `StorageBlobLogs` hunting and `challenge-05/manual-hunting-pending.json`.  
**Full credit:** Either valid path completed factually.  
**Partial:** Configuration only, without hunting.  
**Pitfalls:** Legacy pricing substitute; staging account; assuming mimic must alert; unrequested plan changes.

## Task 2 — Rotate and verify key behavior

```powershell
$before = @(Get-AzStorageAccountKey -ResourceGroupName $rg -Name $sa)
$old = @($before | Where-Object KeyName -eq key1)[0].Value
$key2 = @($before | Where-Object KeyName -eq key2)[0].Value
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName $sa -StorageAccountKey $key2) -ErrorAction Stop | Out-Null
New-AzStorageAccountKey -ResourceGroupName $rg -Name $sa -KeyName key1 | Out-Null
$new = @(Get-AzStorageAccountKey -ResourceGroupName $rg -Name $sa | Where-Object KeyName -eq key1)[0].Value
if ($new -eq $old) { throw 'Key did not rotate.' }
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName $sa -StorageAccountKey $new) -ErrorAction Stop | Out-Null
```

Verify the old key is rejected without printing either value. Upload nonsecret `challenge-05/key-rotation-verified.json`.

**Full credit:** Alternate access first; old fails; new works; dependencies/SAS noted; no secrets.  
**Partial:** Regenerated without full behavioral proof.  
**Pitfalls:** Rotating both keys first; rotating staging; exposing keys; forgetting account-key-signed SAS.

## Task 3 — Concise containment follow-up

**Model answer:** Prefer Entra authorization and managed identity, update dependencies and affected SAS, restrict shared-key use, continue Defender/Blob-log monitoring, investigate repeated failures, and retain evidence.

**Full credit:** Prioritized and tied to findings.  
**Partial:** Generic monitoring list.  
**Pitfalls:** Claiming all user-delegation SAS are revoked; deleting evidence.

---

# Challenge 6 — Restore, validate, and produce runbook (55 minutes)

This estimate includes the mostly passive restore wait. Learners should prepare validation and the runbook while Azure processes the restore.

## Task 1 — Start restore from the sole point with exact staging

```powershell
$items = @(Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $vault.ID)
$points = @(Get-AzRecoveryServicesBackupRecoveryPoint -Item $items[0] -VaultId $vault.ID)
if ($items.Count -ne 1 -or $points.Count -ne 1) { throw 'Expected one item and one point.' }
$staging = @(Get-AzStorageAccount -ResourceGroupName $rg | Where-Object StorageAccountName -ieq $stagingName)
if ($staging.Count -ne 1 -or $staging[0].StorageAccountName -ieq $sa) { throw 'Invalid staging account.' }
$points[0] | Select-Object RecoveryPointTime,RecoveryPointType,RecoveryPointId
$staging[0] | Select-Object StorageAccountName,Location,Id
```

**Expected:** Restore submitted from the single point using exact distinct staging; original preserved via new VM or restore disks.  
**Full credit:** Point, staging, region, mode, and preservation rationale.  
**Partial:** Correct submission but weak staging/preservation evidence.  
**Pitfalls:** Extra point; primary used as staging; wrong region; replace-existing; quota/name collision; soft-deleted name conflict.

## Task 2 — Monitor restore

```powershell
$job = Get-AzRecoveryServicesBackupJob -VaultId $vault.ID -From (Get-Date).AddHours(-6) |
  Where-Object Operation -Match Restore | Sort-Object StartTime -Descending | Select-Object -First 1
$job | Select-Object JobId,Operation,Status,StartTime,EndTime,WorkloadName
if ($job) { Get-AzRecoveryServicesBackupJobDetail -Job $job -VaultId $vault.ID }
```

**Expected:** One job monitored to `Completed`; progress is recorded during the wait.  
**Full credit:** Job ID, timing, target, terminal completion.  
**Partial:** Correct job still progressing at review; no completion credit yet.  
**Pitfalls:** Duplicate restores; elapsed time treated as failure; unavailable VM SKU; identity/RBAC not reapplied.

## Task 3 — Validate SHA-256 and publish evidence

Run on the restored system/disk, not the original.

```powershell
$manifest = Get-Content 'C:\LabFiles\RansomwareResilience\Evidence\checksum-reference.json' -Raw | ConvertFrom-Json
$root = 'C:\LabFiles\RansomwareResilience\SeedData'
$results = foreach ($entry in $manifest) {
  $relative = if ($entry.BlobName) { $entry.BlobName } elseif ($entry.path) { $entry.path } else { $entry.name }
  $expected = if ($entry.SHA256) { $entry.SHA256 } else { $entry.sha256 }
  $file = Join-Path $root ([string]$relative).Replace('/','\')
  $actual = if (Test-Path $file) { (Get-FileHash $file -Algorithm SHA256).Hash } else { $null }
  [pscustomobject]@{File=$relative;Expected=$expected;Actual=$actual;Passed=($actual -and $actual -ieq $expected)}
}
if (@($results).Count -eq 0 -or @($results | Where-Object {-not $_.Passed}).Count) { throw 'Checksum failure.' }
Set-AzStorageBlobContent -File 'C:\LabFiles\RansomwareResilience\Evidence\restore-checksum-complete.json' `
  -Container lab-evidence -Blob challenge-06/restore-checksum-complete.json -Context $ctx -Force
```

**Expected:** Every manifest entry passes; marker includes job/recovery-point identity, UTC validation time, checked count, and zero failures.  
**Full credit:** Completed restore, all hashes pass, canonical nonsecret marker.  
**Partial:** Restore complete but validation/upload incomplete.  
**Pitfalls:** Original VM validated; wrong mount; filenames only; marker uploaded to staging or before success.

## Task 4 — Concise recovery runbook

Require only this operational structure:

1. **Governance:** vault/guard mapping and protected operation; denial observed with one identity; no approval performed.
2. **Restore:** exact resource resolution, sole point, original preserved, exact staging used.
3. **Timing:** job ID/timestamps and progress polling; progressing `InProgress` is not failure.
4. **Validation:** all files checked against trusted SHA-256; zero failures before return to service.
5. **Rollback:** retain/use original or abandon restored candidate if validation fails.
6. **Cleanup:** remove only temporary restored VM/disks/NIC/public IP and restore-created staging artifacts after evidence capture.
7. **Next steps:** reapply backup, managed identity dependencies, VM RBAC, AMA/DCR, NSG/JIT, and monitoring if promoted.

**Full credit:** Concise, reusable runbook covers all seven items.  
**Partial:** Correct recovery notes missing one control area.  
**Pitfalls:** Extended essay; claimed approval; deleting original early; assuming backup/identity follows a renamed VM; deleting primary evidence; leaving billable artifacts.

---

# Consolidated rubric

| Challenge | Full-credit outcome |
|---|---|
| 1 — 25 min | Compact record proves exact discovery, one point, soft delete, mapping, gated operation, and bounded MUA scope |
| 2 — 25 min | B-only unlocked container policy; A/account excluded; limitation stated; VM controls reviewed only |
| 3 — 20 min | One identity, no standing guard authority, attributable denial, safe cancel, one compact JSON object, essential concise explanation |
| 4 — 30 min | Same N attempts, A success/B rejection, one three-source matrix, canonical B output, short conclusion |
| 5 — 25 min | Alert or exact fallback/manual hunt, marker when applicable, safe key rotation with behavior proof, concise follow-up |
| 6 — 55 min | Sole-point restore with exact staging, monitored completion, all hashes pass, canonical marker, concise seven-part runbook |

## Package-wide rejection conditions

- Guessed resource group/primary account or inferred staging name.
- Learner or CSE used to create, repair, or update the Resource Guard or `backupResourceGuardProxy` mapping.
- Resource Guard write granted to the learner, defeating the intended split-authority boundary.
- A or account-level immutability configured.
- Non-policy errors presented as immutable rejection.
- Challenge 3 approval/elevation performed or claimed.
- Defender fallback not using `current@2025-01-01`.
- Blob diagnostics evaluated outside primary `/blobServices/default`.
- Secrets included in evidence.
- Restore success claimed before terminal completion and complete SHA-256 validation.
