using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = $null
$count = 0
$found = $false
$lastFailureSummary = "Tamper protections enabled validation has not completed yet."

$containerAName = "containera-unprotected"
$containerBName = "containerb-protectme"
$evidenceContainerName = "lab-evidence"
$canonicalContainerNames = @($containerAName, $containerBName, $evidenceContainerName)

function Test-TruthyValue {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [string]) { return ($Value -match '^(?i:true|enabled|yes)$') }
    return $false
}

function Test-VersionLevelImmutabilityEnabled {
    param(
        [Parameter(Mandatory = $false)]
        $ImmutableStorageWithVersioning
    )

    if ($null -eq $ImmutableStorageWithVersioning) { return $false }
    if ($ImmutableStorageWithVersioning -is [bool]) { return [bool]$ImmutableStorageWithVersioning }
    if ($ImmutableStorageWithVersioning.PSObject.Properties.Name -contains "Enabled") {
        return (Test-TruthyValue -Value $ImmutableStorageWithVersioning.Enabled)
    }
    if ($ImmutableStorageWithVersioning.PSObject.Properties.Name -contains "enabled") {
        return (Test-TruthyValue -Value $ImmutableStorageWithVersioning.enabled)
    }
    return $false
}

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

function Resolve-ExactLabStorageAccount {
    param(
        [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
        [Parameter(Mandatory = $true)] [string[]] $RequiredContainerNames
    )

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        throw "Resolve-ExactLabStorageAccount requires a non-empty resource group name."
    }

    if ($null -eq $RequiredContainerNames -or $RequiredContainerNames.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount requires at least one canonical container name."
    }

    $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Sort-Object -Property StorageAccountName)
    if ($storageAccounts.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero storage accounts in RG '$ResourceGroupName'. Expected exactly one account containing all canonical containers '$($RequiredContainerNames -join ', ')'."
    }

    $matchesById = @{}
    $inspectionSummaries = New-Object 'System.Collections.Generic.List[string]'

    foreach ($storageAccount in $storageAccounts) {
        $storageAccountName = [string]$storageAccount.StorageAccountName
        $accountId = [string]$storageAccount.Id
        if ([string]::IsNullOrWhiteSpace($accountId)) { $accountId = "$ResourceGroupName/$storageAccountName" }
        $dedupeKey = $accountId.ToLowerInvariant()

        try {
            $storageKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $storageAccountName -ErrorAction Stop | Select-Object -First 1).Value
            if ([string]::IsNullOrWhiteSpace($storageKey)) {
                throw "no account key was returned"
            }

            $context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageKey -ErrorAction Stop
            $containers = @(Get-AzStorageContainer -Context $context -ErrorAction Stop)
            $containerNames = @($containers | ForEach-Object { [string]$_.Name })
            $matchedNames = @($RequiredContainerNames | Where-Object { $containerNames -ccontains $_ })
            $missingNames = @($RequiredContainerNames | Where-Object { -not ($containerNames -ccontains $_) })

            if ($missingNames.Count -eq 0) {
                if (-not $matchesById.ContainsKey($dedupeKey)) {
                    $containerMap = @{}
                    foreach ($container in $containers) {
                        if ($RequiredContainerNames -ccontains [string]$container.Name) {
                            $containerMap[[string]$container.Name] = $container
                        }
                    }

                    $matchesById[$dedupeKey] = [pscustomobject]@{
                        StorageAccount = $storageAccount
                        Context        = $context
                        ContainerMap   = $containerMap
                        ContainerNames  = $containerNames
                    }
                }

                $inspectionSummaries.Add("'$storageAccountName' matched all canonical containers '$($RequiredContainerNames -join ', ')'") | Out-Null
            }
            else {
                $inspectionSummaries.Add("'$storageAccountName' excluded because it is missing canonical container(s): '$($missingNames -join ', ')' (matched: '$($matchedNames -join ', ')')") | Out-Null
            }
        }
        catch {
            $inspectionSummaries.Add("'$storageAccountName' could not be inspected through key-based data-plane container listing: $($_.Exception.Message)") | Out-Null
        }
    }

    $matches = @($matchesById.Values | Sort-Object -Property { $_.StorageAccount.StorageAccountName })
    if ($matches.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero matching storage accounts in RG '$ResourceGroupName'. Expected exactly one account containing all three exact canonical containers '$($RequiredContainerNames -join ', ')'. Staging or unrelated accounts are excluded when those exact containers are absent. Inspected $($storageAccounts.Count) account(s): $($inspectionSummaries -join ' | ')"
    }

    if ($matches.Count -gt 1) {
        $ambiguousAccounts = @($matches | ForEach-Object { [string]$_.StorageAccount.StorageAccountName }) -join ", "
        throw "Resolve-ExactLabStorageAccount found ambiguous storage accounts in RG '$ResourceGroupName': $ambiguousAccounts. Expected exactly one account containing all three exact canonical containers '$($RequiredContainerNames -join ', ')'. Remove duplicate canonical container sets or ensure only the lab account has all canonical containers. Inspected $($storageAccounts.Count) account(s): $($inspectionSummaries -join ' | ')"
    }

    return $matches[0]
}

function Get-ContainerImmutabilityPolicySafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    try {
        return Get-AzRmStorageContainerImmutabilityPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ContainerName $ContainerName -ErrorAction Stop
    }
    catch {
        return $null
    }
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $rg = Resolve-ExactLabResourceGroup -DeploymentId $DID
        $resourceGroup = Get-AzResourceGroup -Name $rg -ErrorAction Stop
        $storageResolution = Resolve-ExactLabStorageAccount -ResourceGroupName $rg -RequiredContainerNames $canonicalContainerNames
        $targetStorage = $storageResolution.StorageAccount
        $targetStorageName = [string]$targetStorage.StorageAccountName

        $containerA = Get-AzRmStorageContainer -ResourceGroupName $rg -StorageAccountName $targetStorageName -Name $containerAName -ErrorAction SilentlyContinue
        $containerB = Get-AzRmStorageContainer -ResourceGroupName $rg -StorageAccountName $targetStorageName -Name $containerBName -ErrorAction SilentlyContinue
        $evidenceContainer = Get-AzStorageContainer -Name $evidenceContainerName -Context $storageResolution.Context -ErrorAction SilentlyContinue

        $accountLevelEnabled = $false
        $accountLevelEvidence = "not enabled"
        if ($null -ne $targetStorage) {
            if ($targetStorage.PSObject.Properties.Name -contains "ImmutableStorageWithVersioning" -and $null -ne $targetStorage.ImmutableStorageWithVersioning) {
                if ($targetStorage.ImmutableStorageWithVersioning.PSObject.Properties.Name -contains "Enabled" -and (Test-TruthyValue -Value $targetStorage.ImmutableStorageWithVersioning.Enabled)) {
                    $accountLevelEnabled = $true
                    $accountLevelEvidence = "enabled on PSStorageAccount.ImmutableStorageWithVersioning.Enabled"
                }
            }

            $storageArm = Get-AzResource -ResourceId $targetStorage.Id -ExpandProperties -ErrorAction SilentlyContinue
            if ($null -ne $storageArm -and $null -ne $storageArm.Properties.immutableStorageWithVersioning -and (Test-TruthyValue -Value $storageArm.Properties.immutableStorageWithVersioning.enabled)) {
                $accountLevelEnabled = $true
                $accountLevelEvidence = "enabled on ARM properties.immutableStorageWithVersioning.enabled"
            }
        }

        $containerBPolicy = $null
        $containerBPolicyOk = $false
        $containerBVersionLevelEnabled = $false
        $containerBPolicyState = "not found"
        $containerBRetentionDays = $null
        if ($null -ne $containerB) {
            $containerBPolicy = Get-ContainerImmutabilityPolicySafe -ResourceGroupName $rg -StorageAccountName $targetStorageName -ContainerName $containerBName
            $containerBVersionLevelEnabled = Test-VersionLevelImmutabilityEnabled -ImmutableStorageWithVersioning $containerB.ImmutableStorageWithVersioning
            if ($null -ne $containerBPolicy) {
                $containerBRetentionDays = $containerBPolicy.ImmutabilityPeriodSinceCreationInDays
                $containerBPolicyState = [string]$containerBPolicy.State
                $containerBPolicyOk = (($null -ne $containerBRetentionDays) -and ([int]$containerBRetentionDays -gt 0) -and (-not $containerBVersionLevelEnabled))
            }
        }

        $containerAPolicy = $null
        $containerAProtected = $false
        $containerAVersionLevelEnabled = $false
        if ($null -ne $containerA) {
            $containerAPolicy = Get-ContainerImmutabilityPolicySafe -ResourceGroupName $rg -StorageAccountName $targetStorageName -ContainerName $containerAName
            $containerAVersionLevelEnabled = Test-VersionLevelImmutabilityEnabled -ImmutableStorageWithVersioning $containerA.ImmutableStorageWithVersioning
            $containerAProtected = (($null -ne $containerAPolicy) -or $containerAVersionLevelEnabled)
        }

        $preChecksOk = ($null -ne $resourceGroup -and $null -ne $targetStorage -and $null -ne $containerA -and $null -ne $containerB -and $null -ne $evidenceContainer)
        $scopeOk = ($containerBPolicyOk -and (-not $accountLevelEnabled) -and (-not $containerAProtected))
        $found = ($preChecksOk -and $scopeOk)

        if ($found) {
            $message = @{
                Status  = "Succeeded"
                Message = "Tamper protections enabled: exact deployment-tag resolver selected RG '$rg'; exact storage resolver selected the sole account '$targetStorageName' containing canonical containers '$($canonicalContainerNames -join ', ')'. Container B '$containerBName' is protected by a container-scoped immutability policy (retention $containerBRetentionDays day(s), state '$containerBPolicyState'); Container A '$containerAName' has no immutability policy; storage account-level immutability is $accountLevelEvidence. If the Container B policy is unlocked, it remains tamper-resistant but can still be changed or removed by an authorized principal."
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
        }
        else {
            $failureDetails = @()
            if ($null -eq $resourceGroup) { $failureDetails += "no resource group was discovered using exact deploymentId/DeploymentID tags '$DID' on resource groups or resources" }
            if ($null -eq $targetStorage) { $failureDetails += "no sole storage account was resolved from exact canonical containers '$($canonicalContainerNames -join ', ')'" }
            if ($null -ne $targetStorage -and $null -eq $containerA) { $failureDetails += "required Container A '$containerAName' was not found by ARM lookup in resolved account '$targetStorageName'; alternate names are not accepted" }
            if ($null -ne $targetStorage -and $null -eq $containerB) { $failureDetails += "required Container B '$containerBName' was not found by ARM lookup in resolved account '$targetStorageName'; alternate names are not accepted" }
            if ($null -ne $targetStorage -and $null -eq $evidenceContainer) { $failureDetails += "required evidence container '$evidenceContainerName' was not found by data-plane lookup in resolved account '$targetStorageName'" }
            if ($null -ne $containerB -and -not $containerBPolicyOk) { $failureDetails += "Container B '$containerBName' does not have the expected container-scoped immutability policy (policy state '$containerBPolicyState', retention '$containerBRetentionDays', version-level enabled '$containerBVersionLevelEnabled')" }
            if ($accountLevelEnabled) { $failureDetails += "storage account-level immutability is incorrectly enabled ($accountLevelEvidence)" }
            if ($containerAProtected) { $failureDetails += "Container A '$containerAName' is protected by immutability but must remain the unprotected positive-control container (container policy present '$($null -ne $containerAPolicy)', version-level enabled '$containerAVersionLevelEnabled')" }

            $lastFailureSummary = "Tamper protections enabled validation failed. $($failureDetails -join '; '). Attempt $count of 3."
            $message = @{
                Status  = "Failed"
                Message = $lastFailureSummary
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
        $lastFailureSummary = "Error during Tamper protections enabled check. Attempt $count of 3. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = $lastFailureSummary
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
        Message = "Tamper protections enabled was not validated in $rgText after 3 attempts. Last result: $lastFailureSummary Confirm exactly one storage account in the resolved resource group contains all canonical containers '$($canonicalContainerNames -join ', ')', exact container '$containerBName' has a container-scoped immutability policy, exact container '$containerAName' has no immutability policy, and storage account-level immutability is not enabled."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
