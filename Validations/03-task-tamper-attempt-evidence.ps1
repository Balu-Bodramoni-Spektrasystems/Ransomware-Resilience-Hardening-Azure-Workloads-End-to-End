using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = $null
$count = 0
$found = $false
$lastFailure = "Tamper attempt evidence captured validation has not completed yet."

$containerAName = "containera-unprotected"
$containerBName = "containerb-protectme"
$evidenceContainerName = "lab-evidence"
$aEvidenceBlobName = "bootstrap/container-a-attack-output.json"
$bEvidenceBlobName = "attacks/container-b/latest-attack-output.json"
$expectedSchema = @("ContainerName", "AttemptedWrites", "SuccessfulWrites", "FailedWrites", "ScriptPath", "Evidence")

function Get-ExactTagValue {
    param(
        [Parameter(Mandatory = $false)] $Tags,
        [Parameter(Mandatory = $true)] [string] $Name
    )

    if ($null -eq $Tags) { return $null }

    if ($Tags -is [hashtable] -or $Tags -is [System.Collections.IDictionary]) {
        foreach ($key in $Tags.Keys) {
            if ([string]$key -ceq $Name) { return [string]$Tags[$key] }
        }
    }
    else {
        $property = $Tags.PSObject.Properties | Where-Object { $_.Name -ceq $Name } | Select-Object -First 1
        if ($null -ne $property) { return [string]$property.Value }
    }

    return $null
}

function Test-ExactDeploymentTag {
    param(
        [Parameter(Mandatory = $false)] $Tags,
        [Parameter(Mandatory = $true)] [string] $DeploymentId
    )

    foreach ($tagName in @("deploymentId", "DeploymentID")) {
        $tagValue = Get-ExactTagValue -Tags $Tags -Name $tagName
        if ($null -ne $tagValue -and $tagValue -ceq $DeploymentId) { return $true }
    }

    return $false
}

function Add-ResourceGroupCandidate {
    param(
        [Parameter(Mandatory = $true)] [System.Collections.Generic.Dictionary[string,object]] $Candidates,
        [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
        [Parameter(Mandatory = $true)] [string] $Source
    )

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) { return }

    if (-not $Candidates.ContainsKey($ResourceGroupName)) {
        $sourceList = New-Object 'System.Collections.Generic.List[string]'
        $sourceList.Add($Source) | Out-Null
        $Candidates[$ResourceGroupName] = [pscustomobject]@{
            ResourceGroupName = $ResourceGroupName
            Sources           = $sourceList
        }
    }
    else {
        if (-not $Candidates[$ResourceGroupName].Sources.Contains($Source)) {
            $Candidates[$ResourceGroupName].Sources.Add($Source) | Out-Null
        }
    }
}

function Resolve-ExactLabResourceGroup {
    param([Parameter(Mandatory = $true)] [string] $DeploymentId)

    if ([string]::IsNullOrWhiteSpace($DeploymentId)) {
        throw "Deployment ID was not supplied to Resolve-ExactLabResourceGroup."
    }

    $candidates = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($tagName in @("deploymentId", "DeploymentID")) {
        $taggedGroups = @(Get-AzResourceGroup -Tag @{ $tagName = $DeploymentId } -ErrorAction SilentlyContinue)
        foreach ($group in $taggedGroups) {
            if (Test-ExactDeploymentTag -Tags $group.Tags -DeploymentId $DeploymentId) {
                Add-ResourceGroupCandidate -Candidates $candidates -ResourceGroupName $group.ResourceGroupName -Source "resource-group exact tag '$tagName=$DeploymentId'"
            }
        }

        $taggedResources = @(Get-AzResource -TagName $tagName -TagValue $DeploymentId -ErrorAction SilentlyContinue)
        foreach ($resource in $taggedResources) {
            if (Test-ExactDeploymentTag -Tags $resource.Tags -DeploymentId $DeploymentId) {
                Add-ResourceGroupCandidate -Candidates $candidates -ResourceGroupName $resource.ResourceGroupName -Source "resource exact tag '$tagName=$DeploymentId' on $($resource.ResourceType)/$($resource.Name)"
            }
        }
    }

    $candidateValues = @($candidates.Values | Sort-Object -Property ResourceGroupName)
    if ($candidateValues.Count -eq 0) {
        throw "Resolve-ExactLabResourceGroup found zero resource groups for DeploymentID '$DeploymentId'. Candidates: none. Expected exactly one resource group with an exact 'deploymentId' or 'DeploymentID' tag value of '$DeploymentId', or at least one exact-tagged resource in that group. Name matching and fixed fallback are intentionally not used."
    }

    if ($candidateValues.Count -gt 1) {
        $candidateText = @($candidateValues | ForEach-Object {
            "$($_.ResourceGroupName) (sources: $($_.Sources -join '; '))"
        }) -join ", "
        throw "Resolve-ExactLabResourceGroup found ambiguous resource groups for DeploymentID '$DeploymentId'. Candidates: $candidateText. Expected exactly one resource group; fix duplicate or misplaced exact deployment tags. Name matching and fixed fallback are intentionally not used."
    }

    return [string]$candidateValues[0].ResourceGroupName
}

function Test-ExactStorageContainerExists {
    param(
        [Parameter(Mandatory = $true)] $Context,
        [Parameter(Mandatory = $true)] [string] $ContainerName
    )

    $matches = @(Get-AzStorageContainer -Name $ContainerName -Context $Context -ErrorAction SilentlyContinue | Where-Object { $_.Name -ceq $ContainerName })
    return ($matches.Count -eq 1)
}

function Resolve-ExactLabStorageAccount {
    param([Parameter(Mandatory = $true)] [string] $ResourceGroupName)

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        throw "Resolve-ExactLabStorageAccount requires a non-empty exact lab resource group name."
    }

    $requiredContainers = @($containerAName, $containerBName, $evidenceContainerName)
    $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop)
    if ($storageAccounts.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero storage accounts in exact RG '$ResourceGroupName'. Expected exactly one account containing exact containers '$($requiredContainers -join ', ')'."
    }

    $candidateMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $inspectionDetails = New-Object 'System.Collections.Generic.List[string]'

    foreach ($storageAccount in $storageAccounts) {
        $storageAccountName = [string]$storageAccount.StorageAccountName
        try {
            $storageKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $storageAccountName -ErrorAction Stop | Select-Object -First 1).Value
            if ([string]::IsNullOrWhiteSpace($storageKey)) {
                throw "no storage account key was returned"
            }

            $context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageKey -ErrorAction Stop
            $missingContainers = New-Object 'System.Collections.Generic.List[string]'

            foreach ($containerName in $requiredContainers) {
                if (-not (Test-ExactStorageContainerExists -Context $context -ContainerName $containerName)) {
                    $missingContainers.Add($containerName) | Out-Null
                }
            }

            if ($missingContainers.Count -eq 0) {
                $dedupeKey = if (-not [string]::IsNullOrWhiteSpace([string]$storageAccount.Id)) { [string]$storageAccount.Id } else { $storageAccountName }
                if (-not $candidateMap.ContainsKey($dedupeKey)) {
                    $candidateMap[$dedupeKey] = [pscustomobject]@{
                        StorageAccount = $storageAccount
                        Context        = $context
                        Containers     = $requiredContainers
                    }
                }
                $inspectionDetails.Add("storage account '$storageAccountName' contains all exact required containers") | Out-Null
            }
            else {
                $inspectionDetails.Add("storage account '$storageAccountName' missing exact container(s): $($missingContainers -join ', ')") | Out-Null
            }
        }
        catch {
            $inspectionDetails.Add("storage account '$storageAccountName' inspection failed: $($_.Exception.Message)") | Out-Null
        }
    }

    $candidates = @($candidateMap.Values)
    if ($candidates.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero storage accounts in exact RG '$ResourceGroupName' containing all required exact containers '$($requiredContainers -join ', ')'. Inspected accounts: $($inspectionDetails -join ' | '). Account ordering, prefix matching, name guessing, and fallback account selection are intentionally not used."
    }

    if ($candidates.Count -gt 1) {
        $candidateText = @($candidates | ForEach-Object { [string]$_.StorageAccount.StorageAccountName }) -join ', '
        throw "Resolve-ExactLabStorageAccount found ambiguous storage accounts in exact RG '$ResourceGroupName'. Candidates containing all exact required containers '$($requiredContainers -join ', ')': $candidateText. Inspected accounts: $($inspectionDetails -join ' | '). Expected exactly one primary lab storage account; account ordering, scoring, first-match selection, prefix matching, and fallback account selection are intentionally not used."
    }

    return $candidates[0]
}

function Convert-ToIntOrNull {
    param($Value)

    if ($null -eq $Value) { return $null }

    try { return [int]$Value }
    catch { return $null }
}

function Get-ExactJsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )

    $property = $Object.PSObject.Properties | Where-Object { $_.Name -ceq $Name } | Select-Object -First 1
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-ExactGeneratedSchema {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string[]] $Schema
    )

    if ($null -eq $Object -or $Object -is [array]) { return $false }

    $actualNames = @($Object.PSObject.Properties | ForEach-Object { $_.Name })

    foreach ($name in $Schema) {
        if (-not ($actualNames -ccontains $name)) { return $false }
    }

    return $true
}

function Get-ScriptFileName {
    param([string] $ScriptPath)

    if ([string]::IsNullOrWhiteSpace($ScriptPath)) { return $null }
    $normalized = $ScriptPath -replace '\\', '/'
    return (($normalized -split '/') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 1)
}

function Test-ImmutabilitySignal {
    param($Value)

    if ($null -eq $Value) { return $false }
    $text = ($Value | Out-String)
    return ($text -match "(?i)BlobImmutableDueToPolicy|immutable|immutability|retention|legal hold|WORM|policy")
}

function Get-EvidenceJson {
    param(
        [Parameter(Mandatory = $true)] $Context,
        [Parameter(Mandatory = $true)] [string] $ContainerName,
        [Parameter(Mandatory = $true)] [string] $BlobName
    )

    $blob = Get-AzStorageBlob -Container $ContainerName -Blob $BlobName -Context $Context -ErrorAction Stop
    if ($null -eq $blob) {
        throw "Evidence blob '$BlobName' was not found in container '$ContainerName'."
    }

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("clv-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    try {
        $destination = Join-Path $tempRoot ([System.IO.Path]::GetFileName(($BlobName -replace '/', [System.IO.Path]::DirectorySeparatorChar)))
        Get-AzStorageBlobContent -Container $ContainerName -Blob $BlobName -Destination $destination -Context $Context -Force -ErrorAction Stop | Out-Null
        $jsonText = Get-Content -Path $destination -Raw -ErrorAction Stop
        return ($jsonText | ConvertFrom-Json -ErrorAction Stop)
    }
    finally {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-StorageEvidenceInResolvedAccount {
    param(
        [Parameter(Mandatory = $true)] $ResolvedStorageAccount,
        [Parameter(Mandatory = $true)] [System.Collections.Generic.List[string]] $Checks,
        [Parameter(Mandatory = $true)] [System.Collections.Generic.List[string]] $Failures
    )

    $storageAccountName = [string]$ResolvedStorageAccount.StorageAccount.StorageAccountName
    $context = $ResolvedStorageAccount.Context

    $Checks.Add("resolved exact primary storage account '$storageAccountName' containing canonical containers '$containerAName', '$containerBName', and '$evidenceContainerName'") | Out-Null
    $Checks.Add("canonical Container A '$containerAName' exists in resolved primary") | Out-Null
    $Checks.Add("canonical Container B '$containerBName' exists in resolved primary") | Out-Null
    $Checks.Add("evidence container '$evidenceContainerName' exists in resolved primary") | Out-Null

    $aEvidence = $null
    $bEvidence = $null

    try {
        $aEvidence = Get-EvidenceJson -Context $context -ContainerName $evidenceContainerName -BlobName $aEvidenceBlobName
        $Checks.Add("Container A evidence blob '$aEvidenceBlobName' exists in resolved primary") | Out-Null
    }
    catch {
        $Failures.Add("Container A evidence blob '$aEvidenceBlobName' is missing or unreadable in resolved primary storage account '$storageAccountName': $($_.Exception.Message)") | Out-Null
    }

    try {
        $bEvidence = Get-EvidenceJson -Context $context -ContainerName $evidenceContainerName -BlobName $bEvidenceBlobName
        $Checks.Add("Container B evidence blob '$bEvidenceBlobName' exists in resolved primary") | Out-Null
    }
    catch {
        $Failures.Add("Container B evidence blob '$bEvidenceBlobName' is missing or unreadable in resolved primary storage account '$storageAccountName': $($_.Exception.Message)") | Out-Null
    }

    if ($null -eq $aEvidence -or $null -eq $bEvidence) { return $false }

    if (-not (Test-ExactGeneratedSchema -Object $aEvidence -Schema $expectedSchema)) {
        $actual = @($aEvidence.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '
        $Failures.Add("Container A evidence must include the required generated properties '$($expectedSchema -join ', ')'. Additional generated metadata fields are allowed. Actual top-level properties: '$actual'.") | Out-Null
    }
    else {
        $Checks.Add("Container A evidence includes the required generated properties") | Out-Null
    }

    if (-not (Test-ExactGeneratedSchema -Object $bEvidence -Schema $expectedSchema)) {
        $actual = @($bEvidence.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '
        $Failures.Add("Container B evidence must include the required generated properties '$($expectedSchema -join ', ')'. Additional generated metadata fields are allowed. Actual top-level properties: '$actual'.") | Out-Null
    }
    else {
        $Checks.Add("Container B evidence includes the required generated properties") | Out-Null
    }

    $aTarget = [string](Get-ExactJsonPropertyValue -Object $aEvidence -Name "ContainerName")
    $bTarget = [string](Get-ExactJsonPropertyValue -Object $bEvidence -Name "ContainerName")
    $aAttempted = Convert-ToIntOrNull (Get-ExactJsonPropertyValue -Object $aEvidence -Name "AttemptedWrites")
    $aSucceeded = Convert-ToIntOrNull (Get-ExactJsonPropertyValue -Object $aEvidence -Name "SuccessfulWrites")
    $aFailed = Convert-ToIntOrNull (Get-ExactJsonPropertyValue -Object $aEvidence -Name "FailedWrites")
    $bAttempted = Convert-ToIntOrNull (Get-ExactJsonPropertyValue -Object $bEvidence -Name "AttemptedWrites")
    $bSucceeded = Convert-ToIntOrNull (Get-ExactJsonPropertyValue -Object $bEvidence -Name "SuccessfulWrites")
    $bFailed = Convert-ToIntOrNull (Get-ExactJsonPropertyValue -Object $bEvidence -Name "FailedWrites")
    $aScriptPath = [string](Get-ExactJsonPropertyValue -Object $aEvidence -Name "ScriptPath")
    $bScriptPath = [string](Get-ExactJsonPropertyValue -Object $bEvidence -Name "ScriptPath")
    $aScriptFile = Get-ScriptFileName -ScriptPath $aScriptPath
    $bScriptFile = Get-ScriptFileName -ScriptPath $bScriptPath

    if ($aTarget -cne $containerAName) {
        $Failures.Add("Container A evidence must identify ContainerName '$containerAName'. Actual ContainerName: '$aTarget'.") | Out-Null
    }
    else {
        $Checks.Add("Container A evidence targets '$containerAName'") | Out-Null
    }

    if ($bTarget -cne $containerBName) {
        $Failures.Add("Container B evidence must identify ContainerName '$containerBName'. Actual ContainerName: '$bTarget'.") | Out-Null
    }
    else {
        $Checks.Add("Container B evidence targets '$containerBName'") | Out-Null
    }

    if ($null -eq $aAttempted -or $aAttempted -le 0) {
        $Failures.Add("Container A evidence must record a positive AttemptedWrites value.") | Out-Null
    }
    elseif ($null -eq $aSucceeded -or $aSucceeded -le 0 -or $aSucceeded -ne $aAttempted) {
        $Failures.Add("Container A evidence must show successful writes for the unprotected positive control. AttemptedWrites=$aAttempted; SuccessfulWrites=$aSucceeded.") | Out-Null
    }
    elseif ($null -eq $aFailed -or $aFailed -ne 0) {
        $Failures.Add("Container A evidence must show FailedWrites=0 for the unprotected positive control. Actual FailedWrites=$aFailed.") | Out-Null
    }
    else {
        $Checks.Add("Container A positive control shows $aSucceeded successful write(s) from $aAttempted attempted write(s)") | Out-Null
    }

    if ($null -eq $bAttempted -or $bAttempted -le 0) {
        $Failures.Add("Container B evidence must record a positive AttemptedWrites value after the learner-triggered attack workflow.") | Out-Null
    }
    elseif ($null -eq $bFailed -or $bFailed -le 0 -or $bFailed -ne $bAttempted) {
        $Failures.Add("Container B evidence must show failed/rejected writes for every attempted protected write. AttemptedWrites=$bAttempted; FailedWrites=$bFailed.") | Out-Null
    }
    elseif ($null -eq $bSucceeded -or $bSucceeded -ne 0) {
        $Failures.Add("Container B evidence must show SuccessfulWrites=0 for the protected tamper attempt. Actual SuccessfulWrites=$bSucceeded.") | Out-Null
    }
    else {
        $Checks.Add("Container B protected attempt shows $bFailed failed/rejected write(s) from $bAttempted attempted write(s)") | Out-Null
    }

    if ($null -ne $aAttempted -and $null -ne $bAttempted -and $aAttempted -gt 0 -and $bAttempted -gt 0 -and $aAttempted -ne $bAttempted) {
        $Failures.Add("Container A and B evidence should represent the same seeded attack workflow. Container A AttemptedWrites=$aAttempted; Container B AttemptedWrites=$bAttempted.") | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($aScriptFile) -or [string]::IsNullOrWhiteSpace($bScriptFile)) {
        $Failures.Add("Both evidence files must include a non-empty ScriptPath with the generated script filename. A ScriptPath='$aScriptPath'; B ScriptPath='$bScriptPath'.") | Out-Null
    }
    elseif ($aScriptFile -cne $bScriptFile) {
        $Failures.Add("Evidence must show the same generated script filename for both attacks. A filename='$aScriptFile'; B filename='$bScriptFile'.") | Out-Null
    }
    elseif ($aScriptFile -notlike "*.ps1") {
        $Failures.Add("The shared generated script filename must be a PowerShell script. Shared filename='$aScriptFile'.") | Out-Null
    }
    else {
        $Checks.Add("both evidence files show the same generated script filename '$aScriptFile'") | Out-Null
    }

    $bEvidenceItems = @(Get-ExactJsonPropertyValue -Object $bEvidence -Name "Evidence")
    if ($null -eq $bEvidenceItems -or $bEvidenceItems.Count -eq 0) {
        $Failures.Add("Container B evidence must include per-item Evidence entries containing immutability error details.") | Out-Null
    }
    else {
        $signalCount = 0
        $errorCount = 0
        foreach ($item in $bEvidenceItems) {
            $errorValue = Get-ExactJsonPropertyValue -Object $item -Name "Error"
            if (-not [string]::IsNullOrWhiteSpace([string]$errorValue)) {
                $errorCount++
                if (Test-ImmutabilitySignal -Value $errorValue) { $signalCount++ }
            }
        }

        if ($null -ne $bFailed -and $bFailed -gt 0 -and $signalCount -lt $bFailed) {
            $Failures.Add("Container B per-item Evidence errors must include immutability signals for each failed/rejected write. FailedWrites=$bFailed; item errors=$errorCount; immutability-signaled errors=$signalCount.") | Out-Null
        }
        else {
            $Checks.Add("Container B per-item Evidence contains $signalCount immutability-signaled error(s)") | Out-Null
        }
    }

    return ($Failures.Count -eq 0)
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $rg = Resolve-ExactLabResourceGroup -DeploymentId $DID
        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction Stop
        $checks = New-Object 'System.Collections.Generic.List[string]'
        $failures = New-Object 'System.Collections.Generic.List[string]'
        $checks.Add("resolved exactly one lab resource group '$($resourceGroup.ResourceGroupName)' from exact deployment tags") | Out-Null

        $resolvedStorageAccount = Resolve-ExactLabStorageAccount -ResourceGroupName $rg
        $found = Test-StorageEvidenceInResolvedAccount -ResolvedStorageAccount $resolvedStorageAccount -Checks $checks -Failures $failures

        if (-not $found) {
            $lastFailure = "Resolved exact primary storage account '$($resolvedStorageAccount.StorageAccount.StorageAccountName)' in RG '$rg', but tamper evidence checks failed: $($failures -join '; ')"
        }

        if ($found) {
            $message = @{
                Status  = "Succeeded"
                Message = "Tamper attempt evidence captured: exact-tag-resolved RG '$rg' and exact container-resolved primary storage account '$($resolvedStorageAccount.StorageAccount.StorageAccountName)' contain '$evidenceContainerName/$aEvidenceBlobName' proving successful writes to '$containerAName' and '$evidenceContainerName/$bEvidenceBlobName' proving immutable rejection for '$containerBName'. Checks: $($checks -join '; ')."
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
        }
        else {
            $message = @{
                Status  = "Failed"
                Message = "Tamper attempt evidence captured validation did not pass. $lastFailure Attempt $count of 3."
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })

            if ($count -lt 3) {
                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        $lastFailure = "Error during Tamper attempt evidence captured check. Attempt $count of 3. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = $lastFailure
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs
# always sees a structured result.
if (-not $found) {
    $rgText = if ([string]::IsNullOrWhiteSpace($rg)) { "not resolved by exact deployment tags for DeploymentID '$DID'" } else { "RG '$rg'" }
    $message = @{
        Status  = "Failed"
        Message = "Tamper attempt evidence captured not validated in $rgText after 3 attempts. $lastFailure Expected one and only one primary storage account in the exact lab RG containing exact containers '$containerAName', '$containerBName', and '$evidenceContainerName'; evidence inspection is performed only in that resolved primary account. Expected JSON blobs '$aEvidenceBlobName' and '$bEvidenceBlobName' in evidence container '$evidenceContainerName' with required generated properties '$($expectedSchema -join ', ')', canonical containers '$containerAName' and '$containerBName', Container A successful writes, Container B failed writes, and per-item immutability error signals."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
