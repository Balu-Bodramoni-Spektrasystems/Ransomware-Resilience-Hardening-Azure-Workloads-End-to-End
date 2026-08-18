using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$count = 0
$found = $false
$rg = $null
$labStorage = $null
$lastFailure = "Backup governance configured validation has not completed yet."

$canonicalContainerNames = @("containera-unprotected", "containerb-protectme", "lab-evidence")

function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $false)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function ConvertTo-ValueArray {
    param([Parameter(Mandatory = $false)]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        return @($Value)
    }

    return @($Value)
}

function Get-TagValue {
    param(
        [Parameter(Mandatory = $false)]$Tags,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    if ($null -eq $Tags) {
        return $null
    }

    foreach ($name in $Names) {
        if ($Tags -is [hashtable] -and $Tags.ContainsKey($name)) {
            return $Tags[$name]
        }

        $tagProperty = $Tags.PSObject.Properties | Where-Object { $_.Name -ieq $name }
        foreach ($property in $tagProperty) {
            return $property.Value
        }

        if ($Tags.Keys) {
            foreach ($tagKey in $Tags.Keys) {
                if ([string]$tagKey -ieq $name) {
                    return $Tags[$tagKey]
                }
            }
        }
    }

    return $null
}

function Get-ExactTagValue {
    param(
        [Parameter(Mandatory = $false)]$Tags,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Tags) {
        return $null
    }

    if ($Tags -is [hashtable] -or $Tags -is [System.Collections.IDictionary]) {
        foreach ($key in $Tags.Keys) {
            if ([string]$key -ceq $Name) {
                return $Tags[$key]
            }
        }
    }
    else {
        foreach ($tagProperty in $Tags.PSObject.Properties) {
            if ($tagProperty.Name -ceq $Name) {
                return $tagProperty.Value
            }
        }
    }

    return $null
}

function Add-ResourceGroupCandidate {
    param(
        [Parameter(Mandatory = $true)]$Candidates,
        [Parameter(Mandatory = $false)][string]$ResourceGroupName
    )

    if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName) -and -not $Candidates.ContainsKey($ResourceGroupName)) {
        $Candidates.Add($ResourceGroupName, $ResourceGroupName)
    }
}

function Resolve-ExactLabResourceGroup {
    param(
        [Parameter(Mandatory = $true)][string]$DeploymentId
    )

    $candidateMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $allGroups = @(Get-AzResourceGroup -ErrorAction Stop)
    foreach ($group in $allGroups) {
        foreach ($tagName in @("deploymentId", "DeploymentID")) {
            $tagValue = Get-ExactTagValue -Tags $group.Tags -Name $tagName
            if ([string]$tagValue -ceq $DeploymentId) {
                Add-ResourceGroupCandidate -Candidates $candidateMap -ResourceGroupName $group.ResourceGroupName
                break
            }
        }
    }

    $allResources = @(Get-AzResource -ErrorAction Stop)
    foreach ($resource in $allResources) {
        foreach ($tagName in @("deploymentId", "DeploymentID")) {
            $tagValue = Get-ExactTagValue -Tags $resource.Tags -Name $tagName
            if ([string]$tagValue -ceq $DeploymentId) {
                Add-ResourceGroupCandidate -Candidates $candidateMap -ResourceGroupName $resource.ResourceGroupName
                break
            }
        }
    }

    $candidates = @($candidateMap.Values | Sort-Object)
    if ($candidates.Count -eq 1) {
        foreach ($candidate in $candidates) {
            return $candidate
        }
    }

    $candidateText = if ($candidates.Count -gt 0) { $candidates -join ", " } else { "none" }
    if ($candidates.Count -eq 0) {
        throw "Resolve-ExactLabResourceGroup found zero resource groups for deployment '$DeploymentId'. Expected exactly one resource group with an exact RG tag or resource tag named 'deploymentId' or 'DeploymentID' whose value exactly equals the deployment ID. Candidates: $candidateText."
    }

    throw "Resolve-ExactLabResourceGroup found ambiguous resource groups for deployment '$DeploymentId'. Expected exactly one resource group, but found $($candidates.Count). Candidates: $candidateText."
}

function Resolve-ExactLabStorageAccount {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceGroupName
    )

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        throw "Resolve-ExactLabStorageAccount requires the exact resolved lab resource group name."
    }

    $requiredContainers = @($script:canonicalContainerNames)
    $storageAccounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop)
    $candidateMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $inspectionSummaries = New-Object 'System.Collections.Generic.List[string]'

    foreach ($storageAccount in ($storageAccounts | Sort-Object -Property StorageAccountName)) {
        $storageAccountName = [string]$storageAccount.StorageAccountName
        if ([string]::IsNullOrWhiteSpace($storageAccountName)) {
            $inspectionSummaries.Add("storage account with blank StorageAccountName was ignored") | Out-Null
            continue
        }

        try {
            $keys = @(Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $storageAccountName -ErrorAction Stop)
            $key1Values = @($keys | Where-Object { [string]$_.KeyName -eq "key1" })
            if ($key1Values.Count -ne 1) {
                $availableKeyNames = @($keys | ForEach-Object { [string]$_.KeyName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ", "
                if ([string]::IsNullOrWhiteSpace($availableKeyNames)) { $availableKeyNames = "none returned" }
                $inspectionSummaries.Add("$storageAccountName: excluded because exactly one current key named 'key1' was not returned (available keys: $availableKeyNames)") | Out-Null
                continue
            }

            $keyValue = $null
            foreach ($key1 in $key1Values) {
                $keyValue = [string]$key1.Value
            }

            if ([string]::IsNullOrWhiteSpace($keyValue)) {
                $inspectionSummaries.Add("$storageAccountName: excluded because key1 did not include a usable value") | Out-Null
                continue
            }

            $context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $keyValue -ErrorAction Stop
            $containers = @(Get-AzStorageContainer -Context $context -ErrorAction Stop)
            $containerNames = @($containers | ForEach-Object { [string]$_.Name } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

            $missingRequired = New-Object 'System.Collections.Generic.List[string]'
            foreach ($requiredContainer in $requiredContainers) {
                if ($containerNames -cnotcontains $requiredContainer) {
                    $missingRequired.Add($requiredContainer) | Out-Null
                }
            }

            $containerSummary = if ($containerNames.Count -gt 0) { (@($containerNames | Sort-Object) -join ", ") } else { "none" }
            if ($missingRequired.Count -eq 0) {
                if (-not $candidateMap.ContainsKey($storageAccountName)) {
                    $candidateMap.Add($storageAccountName, [pscustomobject]@{
                        StorageAccountName = $storageAccountName
                        StorageAccount     = $storageAccount
                        Containers         = @($containerNames | Sort-Object)
                    })
                }
                $inspectionSummaries.Add("$storageAccountName: candidate because all exact canonical containers exist ($($requiredContainers -join ', ')); listed containers: $containerSummary") | Out-Null
            }
            else {
                $inspectionSummaries.Add("$storageAccountName: excluded because missing exact canonical container(s) $($missingRequired -join ', '); listed containers: $containerSummary") | Out-Null
            }
        }
        catch {
            $inspectionSummaries.Add("$storageAccountName: excluded because data-plane container enumeration failed: $($_.Exception.Message)") | Out-Null
        }
    }

    $candidates = @($candidateMap.Values | Sort-Object -Property StorageAccountName)
    if ($candidates.Count -eq 1) {
        foreach ($candidate in $candidates) {
            return $candidate.StorageAccount
        }
    }

    $candidateText = if ($candidates.Count -gt 0) { (@($candidates | ForEach-Object { $_.StorageAccountName }) -join ", ") } else { "none" }
    $inspectionText = if ($inspectionSummaries.Count -gt 0) { $inspectionSummaries -join " | " } else { "no storage accounts were returned from the resource group" }

    if ($candidates.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero matching storage accounts in exact RG '$ResourceGroupName'. A matching lab storage account must contain all exact canonical containers: $($requiredContainers -join ', '). Matched candidates: $candidateText. Inspected accounts: $inspectionText. Staging or unrelated accounts without the full exact container set are intentionally excluded."
    }

    throw "Resolve-ExactLabStorageAccount found ambiguous matching storage accounts in exact RG '$ResourceGroupName'. Expected exactly one account containing all exact canonical containers $($requiredContainers -join ', '), but found $($candidates.Count). Matched candidates: $candidateText. Inspected accounts: $inspectionText. Remove duplicate exact lab container sets or correct the deployment tags."
}

function Get-ResourceGuardOperationSummary {
    param([Parameter(Mandatory = $true)]$ResourceGuard)

    $expandedGuard = $null
    try {
        $expandedGuard = Get-AzResource -ResourceId $ResourceGuard.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
    }
    catch {
        $expandedGuard = $null
    }

    $exclusions = @()
    if ($null -ne $expandedGuard) {
        $exclusions = ConvertTo-ValueArray -Value (Get-PropertyValue -Object $expandedGuard.Properties -Name "vaultCriticalOperationExclusionList")
    }
    $exclusions = @($exclusions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)

    $exclusionText = if ($exclusions.Count -gt 0) { $exclusions -join ", " } else { "none returned" }
    return "Resource Guard '$($ResourceGuard.Name)' is configured for Recovery Services vault critical operations; exclusion list: $exclusionText. Mandatory MUA operations include disabling soft delete or security features and removing MUA protection."
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $rg = Resolve-ExactLabResourceGroup -DeploymentId $DID
        $labStorage = Resolve-ExactLabStorageAccount -ResourceGroupName $rg

        $labResources = @(Get-AzResource -ResourceGroupName $rg -ErrorAction Stop)
        $vaults = @(Get-AzRecoveryServicesVault -ResourceGroupName $rg -ErrorAction Stop | Where-Object {
            $_.Name -eq "rsv-$DID" -or ([string](Get-TagValue -Tags $_.Tags -Names @("deploymentId", "DeploymentID")) -eq $DID)
        })
        if ($vaults.Count -eq 0) {
            $vaults = @(Get-AzRecoveryServicesVault -ResourceGroupName $rg -ErrorAction Stop)
        }

        $vms = @(Get-AzVM -ResourceGroupName $rg -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "labvm-$DID" })
        if ($vms.Count -eq 0) {
            $vms = @(Get-AzVM -ResourceGroupName $rg -ErrorAction SilentlyContinue)
        }

        $resourceGuards = @($labResources | Where-Object {
            $_.ResourceType -eq "Microsoft.DataProtection/resourceGuards" -and
            ($_.Name -eq "rg-mua-$DID" -or ([string](Get-TagValue -Tags $_.Tags -Names @("deploymentId", "DeploymentID")) -eq $DID) -or $_.Name -like "*$DID*")
        })

        if ($vaults.Count -eq 0) {
            $lastFailure = "Backup governance configured validation found RG '$rg' and exact canonical lab storage account '$($labStorage.StorageAccountName)', but no Recovery Services vault was found."
        }
        elseif ($resourceGuards.Count -eq 0) {
            $vaultNameText = @($vaults | ForEach-Object { $_.Name }) -join ", "
            $lastFailure = "Backup governance configured validation found Recovery Services vault(s) '$vaultNameText' in RG '$rg' and exact canonical lab storage account '$($labStorage.StorageAccountName)', but no deployment-matched Microsoft.DataProtection/resourceGuards resource was found."
        }
        elseif ($vms.Count -eq 0) {
            $lastFailure = "Backup governance configured validation found RG '$rg' and exact canonical lab storage account '$($labStorage.StorageAccountName)', but no lab VM was found to verify the protected VM backup item."
        }
        else {
            foreach ($vault in $vaults) {
                $vaultResource = Get-AzResource -ResourceId $vault.ID -ExpandProperties -ErrorAction Stop
                $vaultProperties = $null
                try {
                    $vaultProperties = Get-AzRecoveryServicesVaultProperty -VaultId $vault.ID -ErrorAction Stop
                }
                catch {
                    $vaultProperties = $null
                }

                $backupConfigResource = $null
                try {
                    $backupConfigResource = Get-AzResource -ResourceId "$($vault.ID)/backupconfig/vaultconfig" -ExpandProperties -ErrorAction SilentlyContinue
                }
                catch {
                    $backupConfigResource = $null
                }

                $softDeleteValues = @()
                $softDeleteValues += ConvertTo-ValueArray -Value (Get-PropertyValue -Object $vaultProperties -Name "SoftDeleteFeatureState")
                if ($null -ne $backupConfigResource) {
                    $softDeleteValues += ConvertTo-ValueArray -Value (Get-PropertyValue -Object $backupConfigResource.Properties -Name "softDeleteFeatureState")
                }
                $securitySettings = Get-PropertyValue -Object $vaultResource.Properties -Name "securitySettings"
                $softDeleteSettings = Get-PropertyValue -Object $securitySettings -Name "softDeleteSettings"
                $softDeleteValues += ConvertTo-ValueArray -Value (Get-PropertyValue -Object $softDeleteSettings -Name "softDeleteState")
                $softDeleteValues = @($softDeleteValues | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
                $softDeleteOk = @($softDeleteValues | Where-Object { $_ -in @("Enable", "Enabled", "AlwaysON") }).Count -gt 0

                $labVmIds = @($vms | Select-Object -ExpandProperty Id)
                $labVmNames = @($vms | Select-Object -ExpandProperty Name)

                $cmdletBackupItems = @()
                try {
                    $cmdletBackupItems = @(Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $vault.ID -ErrorAction Stop)
                }
                catch {
                    $cmdletBackupItems = @()
                }

                $protectedCmdletItems = @($cmdletBackupItems | Where-Object {
                    $itemJson = $_ | ConvertTo-Json -Depth 10 -Compress
                    $matchesLabVm = $false
                    foreach ($vmId in $labVmIds) {
                        if ($itemJson -match [regex]::Escape($vmId)) { $matchesLabVm = $true }
                    }
                    foreach ($vmName in $labVmNames) {
                        if ($_.FriendlyName -eq $vmName -or $_.Name -like "*$vmName*" -or $itemJson -match [regex]::Escape($vmName)) { $matchesLabVm = $true }
                    }

                    $isProtected = ($_.ProtectionState -in @("Protected", "ProtectionConfigured", "IRPending")) -or ($_.ProtectionStatus -eq "Healthy")
                    $matchesLabVm -and $isProtected
                })

                $armProtectedItems = @($labResources | Where-Object {
                    $_.ResourceType -eq "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems" -and
                    $_.ResourceId -like "$($vault.ID)/*"
                })
                $matchingArmProtectedItems = @($armProtectedItems | ForEach-Object {
                    $expanded = Get-AzResource -ResourceId $_.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                    if ($null -ne $expanded) { $expanded }
                } | Where-Object {
                    $sourceResourceId = [string](Get-PropertyValue -Object $_.Properties -Name "sourceResourceId")
                    $policyId = [string](Get-PropertyValue -Object $_.Properties -Name "policyId")
                    $protectedItemType = [string](Get-PropertyValue -Object $_.Properties -Name "protectedItemType")
                    $workloadType = [string](Get-PropertyValue -Object $_.Properties -Name "workloadType")
                    ($labVmIds -contains $sourceResourceId) -and
                    (-not [string]::IsNullOrWhiteSpace($policyId)) -and
                    ($protectedItemType -like "*virtualMachines*" -or $workloadType -eq "VM")
                })
                $protectedVmOk = ($protectedCmdletItems.Count -gt 0) -or ($matchingArmProtectedItems.Count -gt 0)

                $mapping = $null
                try {
                    $mapping = Get-AzRecoveryServicesResourceGuardMapping -VaultId $vault.ID -ErrorAction Stop
                }
                catch {
                    $mapping = $null
                }

                $mappingJson = ""
                if ($null -ne $mapping) {
                    $mappingJson = ($mapping | ConvertTo-Json -Depth 10 -Compress)
                }

                $sameRegionGuards = @($resourceGuards | Where-Object { $_.Location -eq $vault.Location })
                $matchingMappedGuards = @($resourceGuards | Where-Object {
                    $mappingJson -match [regex]::Escape($_.ResourceId) -or $mappingJson -match [regex]::Escape($_.Name)
                })
                $resourceGuardOk = $sameRegionGuards.Count -gt 0
                $mappingOk = ($null -ne $mapping) -and ($matchingMappedGuards.Count -gt 0)
                $muaConfigOk = $resourceGuardOk -and $mappingOk

                if ($softDeleteOk -and $protectedVmOk -and $resourceGuardOk -and $mappingOk -and $muaConfigOk) {
                    $found = $true
                    $softDeleteStateText = if ($softDeleteValues.Count -gt 0) { $softDeleteValues -join ", " } else { "not returned" }
                    $guardNames = @($matchingMappedGuards | Select-Object -ExpandProperty Name -Unique)
                    $operationSummaries = @($matchingMappedGuards | ForEach-Object { Get-ResourceGuardOperationSummary -ResourceGuard $_ })
                    $backupItemNames = @()
                    if ($protectedCmdletItems.Count -gt 0) {
                        $backupItemNames = @($protectedCmdletItems | ForEach-Object { if ($_.FriendlyName) { $_.FriendlyName } elseif ($_.Name) { $_.Name } else { "AzureVM backup item" } } | Select-Object -Unique)
                    }
                    else {
                        $backupItemNames = @($matchingArmProtectedItems | ForEach-Object { $_.Name } | Select-Object -Unique)
                    }

                    $message = @{
                        Status  = "Succeeded"
                        Message = "Backup governance configured: discovered exactly one lab RG '$rg' for deployment '$DID' and exactly one canonical lab storage account '$($labStorage.StorageAccountName)' containing containers '$($canonicalContainerNames -join ', ')'. Recovery Services vault '$($vault.Name)' protects VM backup item(s) '$($backupItemNames -join ', ')', soft delete state is '$softDeleteStateText', Resource Guard '$($guardNames -join ', ')' exists in the vault region, the vault has a Resource Guard mapping, and MUA protected-operation configuration is present. $($operationSummaries -join ' ')"
                    } | ConvertTo-Json
                    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::OK
                        Body       = $message
                    })
                    break
                }
                else {
                    $missing = @()
                    if (-not $softDeleteOk) {
                        $stateDetail = if ($softDeleteValues.Count -gt 0) { $softDeleteValues -join ", " } else { "not returned" }
                        $missing += "soft delete is not enabled or AlwaysON (current state: $stateDetail)"
                    }
                    if (-not $protectedVmOk) {
                        $missing += "no protected Azure VM backup item maps to lab VM '$($labVmNames -join ', ')' in vault '$($vault.Name)'"
                    }
                    if (-not $resourceGuardOk) {
                        $missing += "no deployment-matched Resource Guard exists in the same region '$($vault.Location)' as vault '$($vault.Name)'"
                    }
                    if (-not $mappingOk) {
                        $mappingDetail = if ($null -eq $mapping) { "no mapping returned" } else { "mapping does not reference Resource Guard '$($resourceGuards.Name -join ', ')'" }
                        $missing += "Resource Guard mapping/MUA linkage is missing or incorrect for vault '$($vault.Name)' ($mappingDetail)"
                    }
                    if (-not $muaConfigOk) {
                        $missing += "MUA protected-operation configuration could not be confirmed from the Resource Guard mapping"
                    }
                    $lastFailure = "Backup governance configured validation failed for RG '$rg', canonical lab storage account '$($labStorage.StorageAccountName)', and vault '$($vault.Name)': $($missing -join '; ')."
                }
            }
        }

        if (-not $found) {
            $message = @{
                Status  = "Failed"
                Message = "$lastFailure Attempt $count of 3."
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
        $rgText = if ([string]::IsNullOrWhiteSpace($rg)) { "not yet discovered" } else { $rg }
        $lastFailure = "Backup governance configured validation errored while checking RG '$rgText'. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = "Error during Backup governance configured check. Attempt $count of 3. Error: $($_.Exception.Message)"
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
    $rgText = if ([string]::IsNullOrWhiteSpace($rg)) { "not discovered" } else { $rg }
    $storageText = if ($null -eq $labStorage) { "not resolved by exact canonical containers" } else { $labStorage.StorageAccountName }
    $message = @{
        Status  = "Failed"
        Message = "Backup governance configured validation failed after 3 attempts. Lab RG: '$rgText'. Lab storage account: '$storageText'. $lastFailure"
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
