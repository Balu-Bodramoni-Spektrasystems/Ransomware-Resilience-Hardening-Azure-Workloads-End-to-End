Param(
    [string] $AzureUserName,
    [string] $AzurePassword,
    [string] $AzureTenantID,
    [string] $AzureSubscriptionID,
    [string] $ODLID,
    [string] $InstallCloudLabsShadow,
    [string] $DeploymentID,
    [string] $vmAdminUsername,
    [string] $vmAdminPassword,
    [string] $trainerUserName,
    [string] $trainerUserPassword
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

New-Item -ItemType Directory -Path 'C:\WindowsAzure\Logs' -Force | Out-Null
Start-Transcript -Path 'C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt' -Append -Force

$script:StorageContext = $null
$script:EvidenceContainerName = 'lab-evidence'
$script:EvidenceRoot = 'C:\LabFiles\RansomwareResilience\Evidence'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $commonBaseUri = 'https://experienceazure.blob.core.windows.net/templates/cloudlabs-common/'
    $labRoot = 'C:\LabFiles\RansomwareResilience'
    $evidenceRoot = Join-Path $labRoot 'Evidence'
    $scriptRoot = Join-Path $labRoot 'Scripts'
    $seedRoot = Join-Path $labRoot 'SeedData'
    $publicDesktop = 'C:\Users\Public\Desktop'
    $containerAName = 'containera-unprotected'
    $containerBName = 'containerb-protectme'
    $evidenceContainerName = 'lab-evidence'
    $script:EvidenceContainerName = $evidenceContainerName
    $script:EvidenceRoot = $evidenceRoot

    foreach ($path in @('C:\LabFiles', $labRoot, $evidenceRoot, $scriptRoot, $seedRoot, $publicDesktop)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    function Write-Log {
        param([string] $Message)
        $stamp = (Get-Date).ToString('s')
        Write-Host "[$stamp] $Message"
    }

    function ConvertTo-EnvValue {
        param([string] $Value)
        if ($null -eq $Value) { return '""' }
        $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
        return '"' + $escaped + '"'
    }

    function CreateCredFile {
        Write-Log 'Downloading CloudLabs credential helper files from the common CloudLabs location.'
        $downloads = @('AzureCreds.txt', 'AzureCreds.ps1')
        $replacements = [ordered]@{
            '<AzureUserName>'          = $AzureUserName
            '<AzurePassword>'          = $AzurePassword
            '<AzureTenantID>'          = $AzureTenantID
            '<AzureSubscriptionID>'    = $AzureSubscriptionID
            '<ODLID>'                  = $ODLID
            '<DeploymentID>'           = $DeploymentID
            'GET-AZUSER-UPN'           = $AzureUserName
            'GET-AZUSER-PASSWORD'      = $AzurePassword
            'GET-ODL-ID'               = $ODLID
            'GET-DEPLOYMENT-ID'        = $DeploymentID
            'GET-SUBSCRIPTION-ID'      = $AzureSubscriptionID
            'GET-TENANT-ID'            = $AzureTenantID
            'AzureUserNameValue'       = $AzureUserName
            'AzurePasswordValue'       = $AzurePassword
            'AzureTenantIDValue'       = $AzureTenantID
            'AzureSubscriptionIDValue' = $AzureSubscriptionID
        }

        foreach ($fileName in $downloads) {
            $destination = Join-Path 'C:\LabFiles' $fileName
            Invoke-WebRequest -Uri ($commonBaseUri + $fileName) -OutFile $destination -UseBasicParsing
            $content = Get-Content -Path $destination -Raw
            foreach ($key in $replacements.Keys) {
                $content = $content.Replace($key, [string]$replacements[$key])
            }
            Set-Content -Path $destination -Value $content -Encoding UTF8 -Force
            Copy-Item -Path $destination -Destination (Join-Path $publicDesktop $fileName) -Force
        }
    }

    function Ensure-TrainerLocalAccount {
        $shadowRequested = -not ($InstallCloudLabsShadow -match '^(?i:false|0|no)$')
        if (-not $shadowRequested) {
            Write-Log 'InstallCloudLabsShadow was explicitly false; skipping trainer local account creation.'
            return
        }
        if ([string]::IsNullOrWhiteSpace($trainerUserName) -or [string]::IsNullOrWhiteSpace($trainerUserPassword)) {
            Write-Log 'Trainer username or password was not supplied; skipping trainer local account creation.'
            return
        }

        Write-Log "Ensuring trainer local account '$trainerUserName' exists for VM Shadow only. This account is not treated as a Microsoft Entra approver."
        $secureTrainerPassword = ConvertTo-SecureString $trainerUserPassword -AsPlainText -Force
        $existing = Get-LocalUser -Name $trainerUserName -ErrorAction SilentlyContinue
        if ($existing) {
            Set-LocalUser -Name $trainerUserName -Password $secureTrainerPassword -PasswordNeverExpires $true
            Enable-LocalUser -Name $trainerUserName
        }
        else {
            New-LocalUser -Name $trainerUserName -Password $secureTrainerPassword -PasswordNeverExpires -AccountNeverExpires | Out-Null
        }

        foreach ($group in @('Remote Desktop Users', 'Administrators')) {
            try {
                Add-LocalGroupMember -Group $group -Member $trainerUserName -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Message -notmatch 'already.*member') { Write-Log "Could not add $trainerUserName to $group: $($_.Exception.Message)" }
            }
        }
    }

    function Ensure-Module {
        param([string] $Name)
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Write-Log "Installing PowerShell module $Name."
            Install-Module -Name $Name -Scope AllUsers -Force -AllowClobber -Repository PSGallery
        }
        Import-Module $Name -Force
    }

    function Get-InstanceMetadata {
        try {
            return Invoke-RestMethod -Headers @{ Metadata = 'true' } -Method GET -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -TimeoutSec 10
        }
        catch {
            Write-Log "IMDS metadata lookup failed: $($_.Exception.Message)"
            return $null
        }
    }

    function Wait-ProviderRegistration {
        param([string] $ProviderNamespace)
        Write-Log "Registering resource provider $ProviderNamespace if needed."
        Register-AzResourceProvider -ProviderNamespace $ProviderNamespace -ErrorAction SilentlyContinue | Out-Null
        for ($i = 0; $i -lt 30; $i++) {
            $provider = Get-AzResourceProvider -ProviderNamespace $ProviderNamespace -ErrorAction SilentlyContinue
            if ($provider -and (($provider | Select-Object -First 1).RegistrationState -eq 'Registered')) { return }
            Start-Sleep -Seconds 10
        }
        Write-Log "Provider $ProviderNamespace was not confirmed registered before timeout; continuing with deployed resources only."
    }

    function Test-DeploymentTagMatch {
        param($Resource)
        if (-not $Resource -or -not $Resource.Tags -or [string]::IsNullOrWhiteSpace($DeploymentID)) { return $false }
        foreach ($entry in $Resource.Tags.GetEnumerator()) {
            $key = [string]$entry.Key
            if (($key -ceq 'deploymentId' -or $key -ceq 'DeploymentID') -and [string]::Equals([string]$entry.Value, [string]$DeploymentID, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    function Get-ExactlyOneTaggedArmResource {
        param(
            [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
            [Parameter(Mandatory = $true)] [string] $ResourceType,
            [Parameter(Mandatory = $true)] [string] $Description,
            [Parameter(Mandatory = $true)] [string] $ExactName
        )

        $resources = @(Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType $ResourceType -ErrorAction SilentlyContinue | Where-Object { Test-DeploymentTagMatch -Resource $_ })
        $resources = @($resources | Where-Object { [string]::Equals($_.Name, $ExactName, [System.StringComparison]::OrdinalIgnoreCase) })

        if ($resources.Count -eq 0) {
            throw "Required ARM resource not found: $Description ($ResourceType) named '$ExactName' in resource group '$ResourceGroupName' with deployment tag value '$DeploymentID'. The bootstrap will not create fallback resources."
        }
        if ($resources.Count -gt 1) {
            $names = ($resources | Select-Object -ExpandProperty Name) -join ', '
            throw "Ambiguous ARM discovery for $Description ($ResourceType). Expected exactly one tagged resource named '$ExactName' but found $($resources.Count): $names. The bootstrap will not guess or create duplicate resources."
        }
        return $resources[0]
    }

    function Get-StorageAccountKey1 {
        param(
            [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
            [Parameter(Mandatory = $true)] [string] $StorageAccountName
        )

        $keys = @(Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop)
        $key1 = @($keys | Where-Object { [string]::Equals([string]$_.KeyName, 'key1', [System.StringComparison]::OrdinalIgnoreCase) })
        if ($key1.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$key1[0].Value)) {
            $seen = if ($keys.Count -gt 0) { ($keys | ForEach-Object { [string]$_.KeyName }) -join ', ' } else { '(none)' }
            throw "Could not deterministically retrieve storage account key 'key1' for '$StorageAccountName'. Returned key names: $seen."
        }
        return [string]$key1[0].Value
    }

    function New-KeyBasedStorageAccess {
        param(
            [Parameter(Mandatory = $true)] $StorageAccount,
            [Parameter(Mandatory = $true)] [string] $ResourceGroupName
        )

        $accountName = [string]$StorageAccount.StorageAccountName
        if ([string]::IsNullOrWhiteSpace($accountName)) { $accountName = [string]$StorageAccount.Name }
        $key = Get-StorageAccountKey1 -ResourceGroupName $ResourceGroupName -StorageAccountName $accountName
        $context = New-AzStorageContext -StorageAccountName $accountName -StorageAccountKey $key
        return [pscustomobject]@{
            Context = $context
            Key = $key
            ConnectionString = "DefaultEndpointsProtocol=https;AccountName=$accountName;AccountKey=$key;EndpointSuffix=core.windows.net"
        }
    }

    function Resolve-PrimaryLabStorageAccount {
        param(
            [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
            [Parameter(Mandatory = $true)] [string[]] $RequiredContainerNames
        )

        Write-Log "Resolving the primary lab storage account by exact deployment tag and canonical data-plane containers in resource group '$ResourceGroupName'."
        Write-Log "Az.Storage verification uses New-AzStorageContext with StorageAccountName and StorageAccountKey, then Get-AzStorageContainer with Context, matching Microsoft Learn guidance."

        $taggedResources = @(Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Storage/storageAccounts' -ErrorAction Stop | Where-Object { Test-DeploymentTagMatch -Resource $_ })
        if ($taggedResources.Count -eq 0) {
            $allInGroup = @(Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Storage/storageAccounts' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            $allText = if ($allInGroup.Count -gt 0) { $allInGroup -join ', ' } else { '(none)' }
            throw "Primary storage discovery found zero storage accounts in the exact current resource group '$ResourceGroupName' with deployment tag value '$DeploymentID'. Storage accounts present in the group: $allText. Refusing to guess by name prefix, index, or deployment order."
        }

        $candidateReports = New-Object System.Collections.Generic.List[object]
        $matches = New-Object System.Collections.Generic.List[object]

        foreach ($resource in ($taggedResources | Sort-Object -Property Name)) {
            $report = [ordered]@{
                StorageAccountName = [string]$resource.Name
                ResourceId = [string]$resource.ResourceId
                Status = 'Unchecked'
                Containers = @()
                MissingRequiredContainers = @()
                Error = $null
            }

            try {
                $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $resource.Name -ErrorAction Stop
                $access = New-KeyBasedStorageAccess -StorageAccount $account -ResourceGroupName $ResourceGroupName
                $containers = @(Get-AzStorageContainer -Context $access.Context -ErrorAction Stop)
                $containerNames = @($containers | ForEach-Object { [string]$_.Name })
                $report.Containers = @($containerNames | Sort-Object)

                $missing = @()
                foreach ($requiredName in $RequiredContainerNames) {
                    if (-not ($containerNames | Where-Object { [string]::Equals($_, $requiredName, [System.StringComparison]::Ordinal) })) {
                        $missing += $requiredName
                    }
                }
                $report.MissingRequiredContainers = $missing

                if ($missing.Count -eq 0) {
                    $report.Status = 'PrimaryCandidate'
                    $matches.Add([pscustomobject]@{
                        Resource = $resource
                        StorageAccount = $account
                        StorageAccess = $access
                        Containers = @($containerNames | Sort-Object)
                    }) | Out-Null
                }
                else {
                    $report.Status = 'RejectedMissingCanonicalContainers'
                }
            }
            catch {
                $report.Status = 'RejectedDataPlaneOrKeyAccessFailed'
                $report.Error = $_.Exception.Message
            }

            $candidateReports.Add([pscustomobject]$report) | Out-Null
        }

        $candidateSummary = ($candidateReports | ForEach-Object {
            $containersText = if ($_.Containers.Count -gt 0) { $_.Containers -join ',' } else { '(none-or-unavailable)' }
            $missingText = if ($_.MissingRequiredContainers.Count -gt 0) { $_.MissingRequiredContainers -join ',' } else { '(none)' }
            $errorText = if ($_.Error) { "; error=$($_.Error)" } else { '' }
            "$($_.StorageAccountName) [$($_.Status); containers=$containersText; missing=$missingText$errorText]"
        }) -join '; '

        if ($matches.Count -eq 0) {
            throw "Primary storage discovery found zero exact deployment-tagged storage accounts in resource group '$ResourceGroupName' containing all required canonical containers: $($RequiredContainerNames -join ', '). Tagged candidate evaluation: $candidateSummary. Refusing to guess by storage account name prefix, first item, index, or deployment order. The dedicated staging account is expected to be rejected naturally when it lacks the canonical containers."
        }
        if ($matches.Count -gt 1) {
            $ambiguous = ($matches | ForEach-Object { $_.StorageAccount.StorageAccountName }) -join ', '
            throw "Ambiguous primary storage discovery: more than one exact deployment-tagged storage account in resource group '$ResourceGroupName' contains all required canonical containers ($($RequiredContainerNames -join ', ')): $ambiguous. Tagged candidate evaluation: $candidateSummary. Refusing to guess by storage account name prefix, first item, index, or deployment order."
        }

        Write-Log "Resolved primary lab storage account '$($matches[0].StorageAccount.StorageAccountName)' because it is the only exact deployment-tagged account with containers: $($RequiredContainerNames -join ', ')."
        return $matches[0]
    }

    function Assert-BlobContainerExists {
        param([string] $Name, $Context)
        $container = Get-AzStorageContainer -Name $Name -Context $Context -ErrorAction SilentlyContinue
        if (-not $container) {
            throw "Required blob container '$Name' was not found in the deployed storage account. Expected canonical containers are 'containera-unprotected', 'containerb-protectme', and 'lab-evidence'. The bootstrap will not create fallback or duplicate containers."
        }
        return $container
    }

    function New-SeedData {
        param([string] $Root)
        if (Test-Path $Root) { Remove-Item -Path $Root -Recurse -Force }
        New-Item -ItemType Directory -Path $Root -Force | Out-Null

        $files = [ordered]@{
            'workload\finance\payroll-q1.csv' = "EmployeeId,Department,Amount`n1001,Operations,1250.00`n1002,Security,1300.00`n1003,Support,1185.50`n"
            'workload\operations\shift-handover.txt' = "Shift handover checklist`n- Verify backup status`n- Validate application health endpoint`n- Review storage write anomalies`n"
            'workload\engineering\appsettings.json' = '{"service":"claims-api","environment":"training","featureFlags":{"immutableStorageEvidence":true,"restoreValidation":true}}'
            'workload\legal\vendor-contract-summary.txt' = "Vendor contract summary for resilience training.`nThis file is benign sample data used for checksum validation.`n"
            'workload\recovery\restore-validation-notes.md' = "# Restore validation notes`nUse the SHA256 manifest in C:\\LabFiles\\RansomwareResilience\\Evidence to compare restored content.`n"
            'workload\security\incident-timeline-template.csv' = "TimeUtc,Event,Source,Notes`n(fill),Storage overwrite attempt,Blob logs,(fill)`n(fill),Backup restore,Recovery Services,(fill)`n"
        }

        foreach ($relativePath in $files.Keys) {
            $fullPath = Join-Path $Root $relativePath
            New-Item -ItemType Directory -Path (Split-Path $fullPath -Parent) -Force | Out-Null
            Set-Content -Path $fullPath -Value $files[$relativePath] -Encoding UTF8 -Force
        }

        $manifest = foreach ($file in Get-ChildItem -Path $Root -File -Recurse | Sort-Object FullName) {
            $relative = $file.FullName.Substring($Root.Length).TrimStart('\') -replace '\\', '/'
            [pscustomobject]@{
                BlobName = $relative
                Length = $file.Length
                SHA256 = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash
            }
        }
        $manifestPath = Join-Path $evidenceRoot 'checksum-reference.json'
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8 -Force
        $manifest | Export-Csv -Path (Join-Path $evidenceRoot 'checksum-reference.csv') -NoTypeInformation -Force
        return $manifest
    }

    function Get-SeedBlobCount {
        param([string] $ContainerName, $Context)
        $blobs = @(Get-AzStorageBlob -Container $ContainerName -Context $Context -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'workload/*' })
        return $blobs.Count
    }

    function Upload-SeedDataIfNeeded {
        param(
            [string] $ContainerName,
            [string] $Root,
            $Context,
            [int] $ExpectedCount
        )
        $currentCount = Get-SeedBlobCount -ContainerName $ContainerName -Context $Context
        if ($currentCount -ge $ExpectedCount) {
            Write-Log "Container $ContainerName already has $currentCount workload blobs; preserving existing state."
            return
        }

        Write-Log "Uploading deterministic seed data to $ContainerName."
        foreach ($file in Get-ChildItem -Path $Root -File -Recurse | Sort-Object FullName) {
            $blobName = $file.FullName.Substring($Root.Length).TrimStart('\') -replace '\\', '/'
            Set-AzStorageBlobContent -File $file.FullName -Container $ContainerName -Blob $blobName -Context $Context -Force | Out-Null
        }
    }

    function Write-AttackMimicScript {
        param([string] $Path)
        $script = @'
Param(
    [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
    [Parameter(Mandatory = $true)] [string] $StorageAccountName,
    [Parameter(Mandatory = $true)] [string] $ContainerName,
    [Parameter(Mandatory = $false)] [string] $OutputPath = "C:\LabFiles\RansomwareResilience\Evidence\attack-output.json",
    [Parameter(Mandatory = $false)] [string] $AttackLabel = "benign-encryption-mimic",
    [Parameter(Mandatory = $false)] [string] $Prefix = "workload/"
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module Az.Storage -Force

New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null
$tempRoot = Join-Path $env:TEMP ("benign-blob-mimic-" + ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

$result = [ordered]@{
    AttackLabel = $AttackLabel
    ScriptPath = $PSCommandPath
    StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    ResourceGroupName = $ResourceGroupName
    StorageAccountName = $StorageAccountName
    ContainerName = $ContainerName
    Prefix = $Prefix
    AttemptedWrites = 0
    SuccessfulWrites = 0
    FailedWrites = 0
    Evidence = @()
    SafeTrainingNote = 'Benign overwrite mimic only: no malware, no propagation, no key material, and no real encryption is performed.'
}

try {
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
    $key = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName | Where-Object { $_.KeyName -eq 'key1' }).Value
    if ([string]::IsNullOrWhiteSpace($key)) { throw "Could not retrieve key1 for storage account '$StorageAccountName'." }
    $ctx = New-AzStorageContext -StorageAccountName $storageAccount.StorageAccountName -StorageAccountKey $key
    $targets = @(Get-AzStorageBlob -Container $ContainerName -Context $ctx | Where-Object { $_.Name -like ($Prefix + '*') } | Sort-Object Name)

    foreach ($blob in $targets) {
        $result.AttemptedWrites++
        $safeName = ($blob.Name -replace '[\\/:"*?<>|]', '_')
        $downloadPath = Join-Path $tempRoot ("source-" + $safeName)
        $mimicPath = Join-Path $tempRoot ("mimic-" + $safeName)
        $itemEvidence = [ordered]@{
            BlobName = $blob.Name
            AttemptedUtc = (Get-Date).ToUniversalTime().ToString('o')
            OriginalLength = $blob.Length
            OriginalETag = [string]$blob.ICloudBlob.Properties.ETag
            WriteSucceeded = $false
            Error = $null
            MimicSHA256 = $null
        }

        try {
            Get-AzStorageBlobContent -Container $ContainerName -Blob $blob.Name -Destination $downloadPath -Context $ctx -Force | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($downloadPath)
            $encoded = [Convert]::ToBase64String($bytes)
            $mimicContent = @(
                'BENIGN-ENCRYPTION-MIMIC-V1',
                ('AttackLabel=' + $AttackLabel),
                ('OriginalBlob=' + $blob.Name),
                ('OriginalSHA256=' + (Get-FileHash -Algorithm SHA256 -Path $downloadPath).Hash),
                ('GeneratedUtc=' + (Get-Date).ToUniversalTime().ToString('o')),
                'PayloadBase64=',
                $encoded
            ) -join "`n"
            Set-Content -Path $mimicPath -Value $mimicContent -Encoding UTF8 -Force
            $itemEvidence.MimicSHA256 = (Get-FileHash -Algorithm SHA256 -Path $mimicPath).Hash
            Set-AzStorageBlobContent -File $mimicPath -Container $ContainerName -Blob $blob.Name -Context $ctx -Force | Out-Null
            $result.SuccessfulWrites++
            $itemEvidence.WriteSucceeded = $true
        }
        catch {
            $result.FailedWrites++
            $itemEvidence.Error = $_.Exception.Message
        }
        $result.Evidence += [pscustomobject]$itemEvidence
    }
}
finally {
    $result.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $result | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8 -Force
    Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("AttemptedWrites={0}; SuccessfulWrites={1}; FailedWrites={2}; OutputPath={3}" -f $result.AttemptedWrites, $result.SuccessfulWrites, $result.FailedWrites, $OutputPath)
return [pscustomobject]$result
'@
        Set-Content -Path $Path -Value $script -Encoding UTF8 -Force
    }

    function Upload-EvidenceFile {
        param([string] $Path, [string] $BlobName, $Context)
        if (Test-Path $Path) {
            Set-AzStorageBlobContent -File $Path -Container $evidenceContainerName -Blob $BlobName -Context $Context -Force | Out-Null
        }
    }

    function Save-StatusAndUpload {
        param(
            [Parameter(Mandatory = $true)] $StatusObject,
            [Parameter(Mandatory = $true)] [string] $LocalFileName,
            [Parameter(Mandatory = $true)] [string] $BlobName,
            $Context
        )
        $path = Join-Path $evidenceRoot $LocalFileName
        $StatusObject | ConvertTo-Json -Depth 12 | Set-Content -Path $path -Encoding UTF8 -Force
        if ($Context) {
            try { Upload-EvidenceFile -Path $path -BlobName $BlobName -Context $Context } catch { Write-Log "Could not upload status '$BlobName': $($_.Exception.Message)" }
        }
        return $path
    }

    function Verify-RecoveryServicesResourceGuardMapping {
        param(
            [Parameter(Mandatory = $true)] $Vault,
            [Parameter(Mandatory = $true)] $ResourceGuard,
            $Context
        )

        $expectedGuardId = [string]$ResourceGuard.ResourceId
        $status = [ordered]@{
            StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Operation = 'ReadOnlyRecoveryServicesVaultResourceGuardMappingVerification'
            VaultName = $Vault.Name
            VaultId = $Vault.ID
            ResourceGuardName = $ResourceGuard.Name
            ResourceGuardId = $expectedGuardId
            AzRecoveryServicesCommand = 'Get-AzRecoveryServicesResourceGuardMapping -VaultId <vaultId>'
            ArmProxyResourceType = 'Microsoft.RecoveryServices/vaults/backupResourceGuardProxies'
            AzMappingReadAttempted = $false
            AzMappingReadSucceeded = $false
            AzMappingReadError = $null
            ArmProxyReadAttempted = $false
            ArmProxyReadSucceeded = $false
            ArmProxyReadError = $null
            MappingVerified = $false
            ProxyReferencesExpectedGuard = $false
            MappingIdentity = $null
            MappingName = $null
            ProxyResourceId = $null
            ProxyName = $null
            ReadError = $null
            Status = 'NotStarted'
            Note = 'Bootstrap verifies the ARM-deployed Resource Guard proxy only. It does not create, update, or repair the vault-to-Resource Guard mapping with the learner identity.'
            MicrosoftLearnVerifiedCommand = 'Get-AzRecoveryServicesResourceGuardMapping -VaultId vaultId fetches the existing Resource Guard mapping added to the Recovery Services vault.'
        }

        try {
            $status.Status = 'Verifying'
            $azMatchesExpectedGuard = $false
            $armMatchesExpectedGuard = $false

            if (-not (Get-Command -Name Get-AzRecoveryServicesResourceGuardMapping -ErrorAction SilentlyContinue)) {
                $status.AzMappingReadError = 'Az.RecoveryServices module does not expose Get-AzRecoveryServicesResourceGuardMapping on this VM.'
                Write-Log $status.AzMappingReadError
            }
            else {
                $status.AzMappingReadAttempted = $true
                try {
                    $existingMappings = @(Get-AzRecoveryServicesResourceGuardMapping -VaultId $Vault.ID -ErrorAction Stop)
                    $status.AzMappingReadSucceeded = $true
                    foreach ($mapping in $existingMappings) {
                        $mappingJson = $mapping | ConvertTo-Json -Depth 20 -Compress
                        if ($mappingJson.IndexOf($expectedGuardId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $azMatchesExpectedGuard = $true
                            $status.MappingIdentity = if ($mapping.Id) { [string]$mapping.Id } elseif ($mapping.ResourceId) { [string]$mapping.ResourceId } else { [string]$mapping.Name }
                            $status.MappingName = [string]$mapping.Name
                            break
                        }
                    }
                }
                catch {
                    $status.AzMappingReadError = $_.Exception.Message
                    Write-Log "Read-only MUA mapping lookup returned: $($_.Exception.Message)"
                }
            }

            $status.ArmProxyReadAttempted = $true
            try {
                $vaultResourceGroupName = $null
                if ([string]$Vault.ID -match '/resourceGroups/([^/]+)/') { $vaultResourceGroupName = $Matches[1] }
                if ([string]::IsNullOrWhiteSpace($vaultResourceGroupName)) { throw "Could not parse resource group name from vault id '$($Vault.ID)'." }

                $proxies = @(Get-AzResource -ResourceGroupName $vaultResourceGroupName -ResourceType 'Microsoft.RecoveryServices/vaults/backupResourceGuardProxies' -ExpandProperties -ErrorAction Stop | Where-Object {
                    ([string]$_.ResourceId).StartsWith(([string]$Vault.ID + '/backupResourceGuardProxies/'), [System.StringComparison]::OrdinalIgnoreCase)
                })
                $status.ArmProxyReadSucceeded = $true

                foreach ($proxy in $proxies) {
                    $proxyJson = $proxy | ConvertTo-Json -Depth 20 -Compress
                    if ($proxyJson.IndexOf($expectedGuardId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $armMatchesExpectedGuard = $true
                        $status.ProxyResourceId = [string]$proxy.ResourceId
                        $status.ProxyName = [string]$proxy.Name
                        if ([string]::IsNullOrWhiteSpace($status.MappingIdentity)) { $status.MappingIdentity = [string]$proxy.ResourceId }
                        if ([string]::IsNullOrWhiteSpace($status.MappingName)) { $status.MappingName = [string]$proxy.Name }
                        break
                    }
                }
            }
            catch {
                $status.ArmProxyReadError = $_.Exception.Message
                Write-Log "Read-only ARM proxy lookup for backupResourceGuardProxies returned: $($_.Exception.Message)"
            }

            if ($azMatchesExpectedGuard -or $armMatchesExpectedGuard) {
                $status.MappingVerified = $true
                $status.ProxyReferencesExpectedGuard = $true
                $status.Status = 'Verified'
                $status.ReadError = $null
            }
            else {
                $status.Status = 'VerificationFailed'
                $status.ReadError = "Deployment verification failure: the Recovery Services vault backupResourceGuardProxies mapping was not readable or did not reference the exact deployed Resource Guard. VaultId='$($Vault.ID)'; ExpectedResourceGuardId='$expectedGuardId'; AzReadError='$($status.AzMappingReadError)'; ArmReadError='$($status.ArmProxyReadError)'."
                Write-Log $status.ReadError
            }
        }
        catch {
            $status.Status = 'VerificationFailed'
            $status.ReadError = "Deployment verification failure while reading the ARM-deployed Recovery Services vault-to-Resource Guard mapping. VaultId='$($Vault.ID)'; ExpectedResourceGuardId='$expectedGuardId'. Original error: $($_.Exception.Message)"
            Write-Log $status.ReadError
        }
        finally {
            $status.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Save-StatusAndUpload -StatusObject $status -LocalFileName 'mua-mapping-status.json' -BlobName 'bootstrap/mua-mapping-status.json' -Context $Context | Out-Null
        }

        return $status
    }

    function Start-LabVmBackupIfFeasible {
        param(
            [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
            [Parameter(Mandatory = $true)] [string] $VmName,
            [Parameter(Mandatory = $true)] $Vault,
            $Context
        )

        $status = [ordered]@{
            StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
            ResourceGroupName = $ResourceGroupName
            VmName = $VmName
            VaultName = $Vault.Name
            VaultId = $Vault.ID
            ProtectionEnabled = $false
            BackupJobTriggered = $false
            JobId = $null
            JobStatus = $null
            RestoreGuidance = 'Track restore and backup jobs by their Azure Backup job status and progress percentage. Do not assume failure while the job remains queued or in progress; duration varies by platform conditions and VM state.'
            Message = $null
        }

        try {
            $policy = Get-AzRecoveryServicesBackupProtectionPolicy -Name 'vm-same-session-policy' -VaultId $Vault.ID -ErrorAction SilentlyContinue
            if (-not $policy) {
                $policy = Get-AzRecoveryServicesBackupProtectionPolicy -WorkloadType AzureVM -VaultId $Vault.ID | Select-Object -First 1
            }
            if (-not $policy) { throw 'No AzureVM backup protection policy was available in the deployed vault.' }

            $container = $null
            $item = $null
            try {
                $container = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -Status Registered -FriendlyName $VmName -VaultId $Vault.ID -ErrorAction SilentlyContinue
                if ($container) { $item = Get-AzRecoveryServicesBackupItem -Container $container -WorkloadType AzureVM -VaultId $Vault.ID -ErrorAction SilentlyContinue }
            }
            catch { }

            if (-not $item) {
                Write-Log "Enabling Azure Backup protection for VM $VmName in the deployed vault $($Vault.Name)."
                Enable-AzRecoveryServicesBackupProtection -Policy $policy -Name $VmName -ResourceGroupName $ResourceGroupName -VaultId $Vault.ID | Out-Null
            }
            $status.ProtectionEnabled = $true

            for ($i = 0; $i -lt 30 -and -not $item; $i++) {
                Start-Sleep -Seconds 20
                $container = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -Status Registered -FriendlyName $VmName -VaultId $Vault.ID -ErrorAction SilentlyContinue
                if ($container) { $item = Get-AzRecoveryServicesBackupItem -Container $container -WorkloadType AzureVM -VaultId $Vault.ID -ErrorAction SilentlyContinue }
            }
            if (-not $item) { throw 'Backup item was not registered before timeout. Check the Recovery Services vault backup items and retry the on-demand backup when registration completes.' }

            $recentJobs = @(Get-AzRecoveryServicesBackupJob -VaultId $Vault.ID -From (Get-Date).AddHours(-12) -ErrorAction SilentlyContinue | Where-Object { $_.WorkloadName -eq $VmName -and $_.Operation -match 'Backup' })
            $completedRecent = $recentJobs | Where-Object { $_.Status -eq 'Completed' } | Select-Object -First 1
            $inProgressRecent = $recentJobs | Where-Object { $_.Status -eq 'InProgress' } | Select-Object -First 1

            if ($completedRecent) {
                $status.BackupJobTriggered = $true
                $status.JobId = [string]$completedRecent.JobId
                $status.JobStatus = $completedRecent.Status
                $status.Message = 'A same-session VM backup job was already completed.'
            }
            elseif ($inProgressRecent) {
                $status.BackupJobTriggered = $true
                $status.JobId = [string]$inProgressRecent.JobId
                $status.JobStatus = $inProgressRecent.Status
                $status.Message = 'A same-session VM backup job is already in progress. Monitor Azure Backup job status and progress percentage.'
            }
            else {
                Write-Log "Triggering on-demand Azure VM backup for $VmName in the deployed vault $($Vault.Name)."
                $job = Backup-AzRecoveryServicesBackupItem -Item $item -VaultId $Vault.ID
                $status.BackupJobTriggered = $true
                $status.JobId = [string]$job.JobId
                $status.JobStatus = $job.Status
                $status.Message = 'On-demand same-session backup job triggered. Monitor Azure Backup job status and progress percentage until a recovery point is available.'

                $deadline = (Get-Date).AddMinutes(45)
                do {
                    Start-Sleep -Seconds 60
                    $latestJob = Get-AzRecoveryServicesBackupJob -JobId $job.JobId -VaultId $Vault.ID -ErrorAction SilentlyContinue
                    if ($latestJob) { $status.JobStatus = $latestJob.Status }
                } while ((Get-Date) -lt $deadline -and $status.JobStatus -eq 'InProgress')
            }
        }
        catch {
            $status.Message = "Backup bootstrap did not complete. Action: use the deployed Recovery Services vault '$($Vault.Name)' and monitor/trigger the Azure VM backup job from Backup jobs or Backup items. Original error: $($_.Exception.Message)"
            Write-Log $status.Message
        }
        finally {
            $status.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Save-StatusAndUpload -StatusObject $status -LocalFileName 'vm-backup-bootstrap-status.json' -BlobName 'bootstrap/vm-backup-bootstrap-status.json' -Context $Context | Out-Null
        }
        return $status
    }

    CreateCredFile
    Ensure-TrainerLocalAccount

    Write-Log 'Preparing PowerShell package provider and Azure modules.'
    try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue } catch { }
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    }
    foreach ($moduleName in @('Az.Accounts', 'Az.Resources', 'Az.Storage', 'Az.RecoveryServices', 'Az.Compute')) {
        Ensure-Module -Name $moduleName
    }

    Write-Log 'Signing in to Azure non-interactively with the supplied CloudLabs learner identity.'
    $securePassword = ConvertTo-SecureString $AzurePassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($AzureUserName, $securePassword)
    Connect-AzAccount -Credential $credential -Tenant $AzureTenantID -Subscription $AzureSubscriptionID | Out-Null
    Set-AzContext -SubscriptionId $AzureSubscriptionID -TenantId $AzureTenantID | Out-Null

    Wait-ProviderRegistration -ProviderNamespace 'Microsoft.Storage'
    Wait-ProviderRegistration -ProviderNamespace 'Microsoft.RecoveryServices'
    Wait-ProviderRegistration -ProviderNamespace 'Microsoft.DataProtection'

    $metadata = Get-InstanceMetadata
    $resourceGroupName = if ($metadata -and $metadata.resourceGroupName) { $metadata.resourceGroupName } else { (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -match [regex]::Escape($DeploymentID) } | Select-Object -First 1).ResourceGroupName }
    if ([string]::IsNullOrWhiteSpace($resourceGroupName)) { throw 'Could not determine the lab resource group from IMDS or Azure Resource Manager.' }
    $vmName = if ($metadata -and $metadata.name) { $metadata.name } else { "labvm-$DeploymentID" }
    $location = if ($metadata -and $metadata.location) { $metadata.location } else { (Get-AzResourceGroup -Name $resourceGroupName).Location }

    Write-Log "Discovered VM context: resourceGroup=$resourceGroupName; vm=$vmName; location=$location. Discovering exact tagged ARM resources without fallback creation."

    $primaryStorageResolution = Resolve-PrimaryLabStorageAccount -ResourceGroupName $resourceGroupName -RequiredContainerNames @($containerAName, $containerBName, $evidenceContainerName)
    $storageResource = $primaryStorageResolution.Resource
    $storageAccount = $primaryStorageResolution.StorageAccount
    $storageAccess = $primaryStorageResolution.StorageAccess
    $vaultResource = Get-ExactlyOneTaggedArmResource -ResourceGroupName $resourceGroupName -ResourceType 'Microsoft.RecoveryServices/vaults' -Description 'Recovery Services vault' -ExactName "rsv-$DeploymentID"
    $guardResource = Get-ExactlyOneTaggedArmResource -ResourceGroupName $resourceGroupName -ResourceType 'Microsoft.DataProtection/resourceGuards' -Description 'Resource Guard for Azure Backup MUA' -ExactName "rg-mua-$DeploymentID"

    $vault = Get-AzRecoveryServicesVault -ResourceGroupName $resourceGroupName -Name $vaultResource.Name -ErrorAction Stop
    $resourceGuard = $guardResource

    Write-Log "Using deployed primary storage account $($storageAccount.StorageAccountName), vault $($vault.Name), and Resource Guard $($resourceGuard.Name)."

    $ctx = $storageAccess.Context
    $script:StorageContext = $ctx

    Assert-BlobContainerExists -Name $containerAName -Context $ctx | Out-Null
    Assert-BlobContainerExists -Name $containerBName -Context $ctx | Out-Null
    Assert-BlobContainerExists -Name $evidenceContainerName -Context $ctx | Out-Null

    $manifest = New-SeedData -Root $seedRoot
    $expectedSeedCount = @($manifest).Count
    Upload-SeedDataIfNeeded -ContainerName $containerAName -Root $seedRoot -Context $ctx -ExpectedCount $expectedSeedCount
    Upload-SeedDataIfNeeded -ContainerName $containerBName -Root $seedRoot -Context $ctx -ExpectedCount $expectedSeedCount

    $attackScriptPath = Join-Path $scriptRoot 'Invoke-BenignBlobEncryptionMimic.ps1'
    Write-AttackMimicScript -Path $attackScriptPath

    $containerAAttackOutputPath = Join-Path $evidenceRoot 'container-a-attack-output.json'
    $containerAAttackMarkerPath = Join-Path $evidenceRoot '.container-a-attack-complete'
    $cloudEvidence = Get-AzStorageBlob -Container $evidenceContainerName -Blob 'bootstrap/container-a-attack-output.json' -Context $ctx -ErrorAction SilentlyContinue
    if ((-not (Test-Path $containerAAttackMarkerPath)) -and $cloudEvidence) {
        Write-Log 'Found existing cloud evidence for the Container A deployment attack; downloading it locally and not re-running the positive-control attack.'
        Get-AzStorageBlobContent -Container $evidenceContainerName -Blob 'bootstrap/container-a-attack-output.json' -Destination $containerAAttackOutputPath -Context $ctx -Force | Out-Null
        "CompletedUtc=$((Get-Date).ToUniversalTime().ToString('o')); Source=ExistingCloudEvidence" | Set-Content -Path $containerAAttackMarkerPath -Encoding UTF8 -Force
    }

    if (-not (Test-Path $containerAAttackMarkerPath)) {
        Write-Log 'Running the benign encryption mimic against unprotected Container A only.'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $attackScriptPath -ResourceGroupName $resourceGroupName -StorageAccountName $storageAccount.StorageAccountName -ContainerName $containerAName -OutputPath $containerAAttackOutputPath -AttackLabel 'deployment-positive-control-container-a'
        if (Test-Path $containerAAttackOutputPath) {
            $attackResult = Get-Content -Path $containerAAttackOutputPath -Raw | ConvertFrom-Json
            "CompletedUtc=$((Get-Date).ToUniversalTime().ToString('o')); AttemptedWrites=$($attackResult.AttemptedWrites); SuccessfulWrites=$($attackResult.SuccessfulWrites); FailedWrites=$($attackResult.FailedWrites)" | Set-Content -Path $containerAAttackMarkerPath -Encoding UTF8 -Force
        }
        else {
            throw 'Container A attack mimic did not write its output file.'
        }
    }
    else {
        Write-Log 'Container A benign attack mimic evidence is already present; preserving existing evidence and blob state.'
    }

    Upload-EvidenceFile -Path (Join-Path $evidenceRoot 'checksum-reference.json') -BlobName 'bootstrap/checksum-reference.json' -Context $ctx
    Upload-EvidenceFile -Path (Join-Path $evidenceRoot 'checksum-reference.csv') -BlobName 'bootstrap/checksum-reference.csv' -Context $ctx
    Upload-EvidenceFile -Path $containerAAttackOutputPath -BlobName 'bootstrap/container-a-attack-output.json' -Context $ctx

    $muaStatus = Verify-RecoveryServicesResourceGuardMapping -Vault $vault -ResourceGuard $resourceGuard -Context $ctx

    $envPath = Join-Path $labRoot '.env'
    $envLines = @(
        "AZURE_SUBSCRIPTION_ID=$(ConvertTo-EnvValue $AzureSubscriptionID)",
        "AZURE_TENANT_ID=$(ConvertTo-EnvValue $AzureTenantID)",
        "ODLID=$(ConvertTo-EnvValue $ODLID)",
        "DEPLOYMENT_ID=$(ConvertTo-EnvValue $DeploymentID)",
        "RESOURCE_GROUP_NAME=$(ConvertTo-EnvValue $resourceGroupName)",
        "VM_NAME=$(ConvertTo-EnvValue $vmName)",
        "LOCATION=$(ConvertTo-EnvValue $location)",
        "STORAGE_ACCOUNT_NAME=$(ConvertTo-EnvValue $storageAccount.StorageAccountName)",
        "AZURE_STORAGE_CONNECTION_STRING=$(ConvertTo-EnvValue $storageAccess.ConnectionString)",
        "CONTAINER_A_NAME=$(ConvertTo-EnvValue $containerAName)",
        "CONTAINER_B_NAME=$(ConvertTo-EnvValue $containerBName)",
        "EVIDENCE_CONTAINER_NAME=$(ConvertTo-EnvValue $evidenceContainerName)",
        "RECOVERY_SERVICES_VAULT_NAME=$(ConvertTo-EnvValue $vault.Name)",
        "RECOVERY_SERVICES_VAULT_ID=$(ConvertTo-EnvValue $vault.ID)",
        "RESOURCE_GUARD_NAME=$(ConvertTo-EnvValue $resourceGuard.Name)",
        "RESOURCE_GUARD_ID=$(ConvertTo-EnvValue $resourceGuard.ResourceId)",
        "MUA_MAPPING_STATUS=$(ConvertTo-EnvValue $muaStatus.Status)",
        "MUA_MAPPING_PROXY_ID=$(ConvertTo-EnvValue $muaStatus.ProxyResourceId)",
        "MUA_MAPPING_IDENTITY=$(ConvertTo-EnvValue $muaStatus.MappingIdentity)",
        "MUA_MAPPING_READ_ERROR=$(ConvertTo-EnvValue $muaStatus.ReadError)",
        "ATTACK_SCRIPT_PATH=$(ConvertTo-EnvValue $attackScriptPath)",
        "CONTAINER_A_ATTACK_OUTPUT=$(ConvertTo-EnvValue $containerAAttackOutputPath)",
        "CHECKSUM_REFERENCE_JSON=$(ConvertTo-EnvValue (Join-Path $evidenceRoot 'checksum-reference.json'))",
        "CHECKSUM_REFERENCE_CSV=$(ConvertTo-EnvValue (Join-Path $evidenceRoot 'checksum-reference.csv'))",
        "RESTORE_GUIDANCE=$(ConvertTo-EnvValue 'Track restore jobs by Azure Backup job status and progress percentage. Duration varies; do not assume failure while the job remains queued or in progress.')"
    )
    $envLines | Set-Content -Path $envPath -Encoding UTF8 -Force
    Copy-Item -Path $envPath -Destination (Join-Path $publicDesktop 'RansomwareResilience.env') -Force

    $readmePath = Join-Path $labRoot 'README-FIRST.txt'
    @"
Ransomware Resilience lab bootstrap is complete.

Key paths:
- Environment file: $envPath
- Benign attack mimic script: $attackScriptPath
- Container A deployment attack evidence: $containerAAttackOutputPath
- Checksum reference: $(Join-Path $evidenceRoot 'checksum-reference.json')

Important lab state:
- $containerAName was seeded and then intentionally overwritten by the benign deployment-time mimic.
- $containerBName was seeded identically and was not attacked or made immutable during bootstrap.
- The vault-to-Resource Guard MUA mapping was verified read-only from the ARM-deployed backupResourceGuardProxies proxy. Bootstrap does not create, update, or repair this mapping with the learner identity.
- Cloud-visible bootstrap evidence is uploaded under bootstrap/ in the $evidenceContainerName container.
- Azure Backup restore duration is progress-based: monitor the restore job status and progress percentage; do not assume failure while the job remains queued or in progress.
- The local trainerUserName account is only for CloudLabs VM Shadow/RDP support and is not a Microsoft Entra approver identity.
"@ | Set-Content -Path $readmePath -Encoding UTF8 -Force
    Copy-Item -Path $readmePath -Destination (Join-Path $publicDesktop 'Ransomware Resilience - README FIRST.txt') -Force

    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut((Join-Path $publicDesktop 'Ransomware Resilience Lab Files.lnk'))
        $shortcut.TargetPath = $labRoot
        $shortcut.Save()
    }
    catch { Write-Log "Desktop shortcut creation skipped: $($_.Exception.Message)" }

    $backupStatus = Start-LabVmBackupIfFeasible -ResourceGroupName $resourceGroupName -VmName $vmName -Vault $vault -Context $ctx

    $bootstrapSummary = [ordered]@{
        CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ResourceGroupName = $resourceGroupName
        VmName = $vmName
        StorageAccountName = $storageAccount.StorageAccountName
        StorageAccountId = $storageAccount.Id
        ContainerAName = $containerAName
        ContainerBName = $containerBName
        EvidenceContainerName = $evidenceContainerName
        RecoveryServicesVaultName = $vault.Name
        RecoveryServicesVaultId = $vault.ID
        ResourceGuardName = $resourceGuard.Name
        ResourceGuardId = $resourceGuard.ResourceId
        MuaMappingStatus = $muaStatus.Status
        MuaMappingVerified = $muaStatus.MappingVerified
        MuaMappingProxyResourceId = $muaStatus.ProxyResourceId
        MuaMappingIdentity = $muaStatus.MappingIdentity
        MuaMappingReadError = $muaStatus.ReadError
        BackupJobStatus = $backupStatus.JobStatus
        BackupMessage = $backupStatus.Message
        AttackScriptPath = $attackScriptPath
        ContainerAAttackOutputPath = $containerAAttackOutputPath
        ChecksumReferencePath = Join-Path $evidenceRoot 'checksum-reference.json'
        BackupStatusPath = Join-Path $evidenceRoot 'vm-backup-bootstrap-status.json'
        RestoreGuidance = 'Track Azure Backup restore job status and progress percentage; duration varies and queued/in-progress does not indicate failure.'
        ContainerBImmutabilityConfiguredByBootstrap = $false
        ContainerBAttackedByBootstrap = $false
        FallbackResourcesCreatedByBootstrap = $false
        MuaMappingVerificationMethod = 'Read-only verification using Get-AzRecoveryServicesResourceGuardMapping and ARM read of Microsoft.RecoveryServices/vaults/backupResourceGuardProxies; bootstrap does not create or update the mapping with the learner identity.'
        PrimaryStorageDiscoveryMethod = 'Exact deployment-tagged storage accounts in current RG filtered by data-plane presence of containera-unprotected, containerb-protectme, and lab-evidence; exactly one required.'
    }
    Save-StatusAndUpload -StatusObject $bootstrapSummary -LocalFileName 'bootstrap-summary.json' -BlobName 'bootstrap/bootstrap-summary.json' -Context $ctx | Out-Null

    Write-Log 'Stage 1 CloudLabs VM bootstrap completed successfully.'
}
catch {
    $failure = [ordered]@{
        CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Status = 'Failed'
        Error = $_.Exception.Message
        ScriptStackTrace = $_.ScriptStackTrace
        Action = 'Review C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt. Confirm the ARM deployment produced exactly one current-RG deployment-tagged primary storage account that contains containera-unprotected, containerb-protectme, and lab-evidence; the bootstrap intentionally refuses storage name-prefix, first/index, or deployment-order guessing.'
    }
    try {
        $failurePath = Join-Path $script:EvidenceRoot 'bootstrap-failure.json'
        New-Item -ItemType Directory -Path (Split-Path $failurePath -Parent) -Force | Out-Null
        $failure | ConvertTo-Json -Depth 8 | Set-Content -Path $failurePath -Encoding UTF8 -Force
        if ($script:StorageContext) {
            Set-AzStorageBlobContent -File $failurePath -Container $script:EvidenceContainerName -Blob 'bootstrap/bootstrap-failure.json' -Context $script:StorageContext -Force | Out-Null
        }
    }
    catch { Write-Host "Could not persist bootstrap failure evidence: $($_.Exception.Message)" }
    Write-Host "CloudLabs bootstrap failed: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace
    throw
}
finally {
    Stop-Transcript
}
