using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = $null
$count = 0
$found = $false

$containerAName = 'containera-unprotected'
$containerBName = 'containerb-protectme'
$evidenceContainerName = 'lab-evidence'
$canonicalContainerNames = @($containerAName, $containerBName, $evidenceContainerName)

function Get-ExactTagValue {
    param(
        [Parameter(Mandatory = $false)] $Resource,
        [Parameter(Mandatory = $true)] [string] $Key
    )

    if ($null -eq $Resource -or $null -eq $Resource.Tags) { return $null }
    foreach ($tagKey in $Resource.Tags.Keys) {
        if ([string]$tagKey -ceq $Key) { return [string]$Resource.Tags[$tagKey] }
    }
    return $null
}

function Add-ResourceGroupCandidate {
    param(
        [Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Candidates,
        [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
        [Parameter(Mandatory = $true)] [string] $Source
    )

    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) { return }
    if (-not $Candidates.Contains($ResourceGroupName)) {
        $Candidates[$ResourceGroupName] = [ordered]@{
            Name    = $ResourceGroupName
            Sources = New-Object System.Collections.Generic.List[string]
        }
    }
    if (-not $Candidates[$ResourceGroupName].Sources.Contains($Source)) {
        $Candidates[$ResourceGroupName].Sources.Add($Source)
    }
}

function Resolve-ExactLabResourceGroup {
    param([Parameter(Mandatory = $true)] [string] $DeploymentId)

    if ([string]::IsNullOrWhiteSpace($DeploymentId)) {
        throw "Cannot resolve the lab resource group because the injected deployment id is empty."
    }

    $candidates = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $tagNames = @('deploymentId', 'DeploymentID')

    foreach ($group in @(Get-AzResourceGroup -ErrorAction Stop)) {
        foreach ($tagName in $tagNames) {
            $tagValue = Get-ExactTagValue -Resource $group -Key $tagName
            if ($null -ne $tagValue -and $tagValue -ceq $DeploymentId) {
                Add-ResourceGroupCandidate -Candidates $candidates -ResourceGroupName $group.ResourceGroupName -Source "resource group tag $tagName=$DeploymentId"
            }
        }
    }

    foreach ($tagName in $tagNames) {
        $taggedResources = @(Get-AzResource -TagName $tagName -TagValue $DeploymentId -ErrorAction Stop)
        foreach ($resource in $taggedResources) {
            $tagValue = Get-ExactTagValue -Resource $resource -Key $tagName
            if ($null -ne $tagValue -and $tagValue -ceq $DeploymentId -and -not [string]::IsNullOrWhiteSpace($resource.ResourceGroupName)) {
                Add-ResourceGroupCandidate -Candidates $candidates -ResourceGroupName $resource.ResourceGroupName -Source "resource tag $tagName=$DeploymentId on $($resource.ResourceType)/$($resource.Name)"
            }
        }
    }

    $candidateRows = @($candidates.Values | Sort-Object Name)
    $candidateSummary = if ($candidateRows.Count -gt 0) {
        ($candidateRows | ForEach-Object { "'$($_.Name)' [sources: $($_.Sources -join '; ')]" }) -join ', '
    }
    else { '(none)' }

    if ($candidateRows.Count -eq 0) {
        throw "No lab resource group was found for deployment '$DeploymentId'. Discovery uses only exact 'deploymentId' or 'DeploymentID' tag values on resource groups and exact-tagged resources; no name matching or fixed fallback is allowed. Candidates: $candidateSummary."
    }
    if ($candidateRows.Count -gt 1) {
        throw "Ambiguous lab resource group for deployment '$DeploymentId'. Exact 'deploymentId'/'DeploymentID' tag discovery returned $($candidateRows.Count) candidates: $candidateSummary. Ensure exactly one resource group, or resources in exactly one resource group, carry the deployment tag value."
    }
    return [string]$candidateRows[0].Name
}

function Resolve-ExactLabStorageAccount {
    param([Parameter(Mandatory = $true)] [string] $ResourceGroupName)

    $accounts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop)
    if ($accounts.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero storage accounts in RG '$ResourceGroupName'. Expected exactly one primary lab storage account containing canonical containers '$($canonicalContainerNames -join ', ')'."
    }

    $candidateMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $inspection = New-Object System.Collections.Generic.List[string]

    foreach ($account in ($accounts | Sort-Object -Property StorageAccountName)) {
        try {
            $keys = @(Get-AzStorageAccountKey -ResourceGroupName $account.ResourceGroupName -Name $account.StorageAccountName -ErrorAction Stop)
            $key = ($keys | Where-Object { $_.KeyName -eq 'key1' } | Select-Object -First 1).Value
            if ([string]::IsNullOrWhiteSpace($key)) { $key = ($keys | Select-Object -First 1).Value }
            if ([string]::IsNullOrWhiteSpace($key)) { throw "no storage account key was returned" }

            $ctx = New-AzStorageContext -StorageAccountName $account.StorageAccountName -StorageAccountKey $key -ErrorAction Stop
            $present = New-Object System.Collections.Generic.List[string]
            $missing = New-Object System.Collections.Generic.List[string]

            foreach ($containerName in $canonicalContainerNames) {
                $container = Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue
                if ($null -ne $container) { $present.Add($containerName) }
                else { $missing.Add($containerName) }
            }

            if ($missing.Count -eq 0) {
                $dedupeKey = if (-not [string]::IsNullOrWhiteSpace([string]$account.Id)) { [string]$account.Id } else { [string]$account.StorageAccountName }
                if (-not $candidateMap.ContainsKey($dedupeKey)) {
                    $candidateMap[$dedupeKey] = [pscustomobject]@{
                        StorageAccount = $account
                        Context        = $ctx
                        Detail         = "storage account '$($account.StorageAccountName)' contains all canonical containers '$($canonicalContainerNames -join ', ')'"
                    }
                }
                $inspection.Add("'$($account.StorageAccountName)': primary candidate; found all canonical containers '$($canonicalContainerNames -join ', ')'")
            }
            else {
                $foundText = if ($present.Count -gt 0) { $present -join ', ' } else { 'none' }
                $inspection.Add("'$($account.StorageAccountName)': excluded; found canonical containers [$foundText], missing [$($missing -join ', ')]. Staging or auxiliary accounts are excluded because they do not contain all canonical containers.")
            }
        }
        catch {
            $inspection.Add("'$($account.StorageAccountName)': inspection error while obtaining data-plane context or listing canonical containers: $($_.Exception.Message)")
        }
    }

    $candidates = @($candidateMap.Values | Sort-Object { $_.StorageAccount.StorageAccountName })
    $inspectionText = if ($inspection.Count -gt 0) { $inspection -join ' | ' } else { 'no accounts inspected' }

    if ($candidates.Count -eq 0) {
        throw "Resolve-ExactLabStorageAccount found zero primary lab storage accounts in RG '$ResourceGroupName'. Expected exactly one account containing all three canonical containers '$($canonicalContainerNames -join ', ')'. No prefixes, guessed names, or first-result selection are used. Inspection: $inspectionText"
    }
    if ($candidates.Count -gt 1) {
        $candidateNames = ($candidates | ForEach-Object { $_.StorageAccount.StorageAccountName }) -join ', '
        throw "Resolve-ExactLabStorageAccount found ambiguous primary lab storage accounts in RG '$ResourceGroupName': $candidateNames. Exactly one account must contain all three canonical containers '$($canonicalContainerNames -join ', ')'. Inspection: $inspectionText"
    }

    return $candidates[0]
}

function Has-JsonProperty {
    param([Parameter(Mandatory = $false)] $Payload, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Payload -or $null -eq $Payload.PSObject -or $null -eq $Payload.PSObject.Properties) { return $false }
    return @($Payload.PSObject.Properties.Name | Where-Object { $_ -eq $Name }).Count -gt 0
}

function Get-JsonPropertyValue {
    param([Parameter(Mandatory = $false)] $Payload, [Parameter(Mandatory = $true)] [string] $Name)
    if (-not (Has-JsonProperty -Payload $Payload -Name $Name)) { return $null }
    return $Payload.PSObject.Properties[$Name].Value
}

function ConvertTo-ArrayValue {
    param([Parameter(Mandatory = $false)] $Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

function Test-TruthyValue {
    param([Parameter(Mandatory = $false)] $Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    $text = ([string]$Value).Trim()
    return $text -in @('true', 'True', 'TRUE', 'enabled', 'Enabled', 'ENABLED', 'yes', 'Yes', 'YES', '1')
}

function Test-FalseBooleanValue {
    param([Parameter(Mandatory = $false)] $Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return -not [bool]$Value }
    return (([string]$Value).Trim() -in @('false', 'False', 'FALSE', '0', 'no', 'No', 'NO'))
}

function Test-BooleanLikeValue {
    param([Parameter(Mandatory = $false)] $Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $true }
    return (([string]$Value).Trim() -in @('true', 'True', 'TRUE', 'false', 'False', 'FALSE', '0', '1', 'yes', 'Yes', 'YES', 'no', 'No', 'NO'))
}

function Test-UtcTimestamp {
    param([Parameter(Mandatory = $false)] $Value)
    if ($null -eq $Value) { return $false }
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($text, [ref]$parsed)) { return $false }
    return ($text.EndsWith('Z', [System.StringComparison]::OrdinalIgnoreCase) -or ($text -match '[+-]\d{2}:\d{2}$'))
}

function Test-RequiredJsonProperties {
    param([Parameter(Mandatory = $false)] $Payload, [Parameter(Mandatory = $true)] [string[]] $RequiredProperties)
    $missing = @()
    foreach ($name in $RequiredProperties) {
        if (-not (Has-JsonProperty -Payload $Payload -Name $name)) { $missing += $name }
    }
    return $missing
}

function Test-NonEmptyEvidenceField {
    param([Parameter(Mandatory = $false)] $Payload, [Parameter(Mandatory = $true)] [string] $Name)
    if (-not (Has-JsonProperty -Payload $Payload -Name $Name)) { return $false }
    $value = Get-JsonPropertyValue -Payload $Payload -Name $Name
    if ($null -eq $value) { return $false }
    if ($value -is [System.Array]) {
        return (@($value) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
    }
    return -not [string]::IsNullOrWhiteSpace([string]$value)
}

function Test-EvidenceBlob {
    param([Parameter(Mandatory = $true)] $ResolvedStorageAccount, [Parameter(Mandatory = $true)] [string] $BlobName)

    $containerName = $evidenceContainerName
    $account = $ResolvedStorageAccount.StorageAccount
    $ctx = $ResolvedStorageAccount.Context
    $tempDir = $null

    try {
        $blob = Get-AzStorageBlob -Container $containerName -Blob $BlobName -Context $ctx -ErrorAction SilentlyContinue
        if ($null -eq $blob) {
            return @{ Found = $false; Valid = $false; Location = ''; Payload = $null; Detail = "Blob '$BlobName' was not found in canonical evidence container '$containerName' on resolved primary storage account '$($account.StorageAccountName)'."; Account = $account }
        }

        $tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("cl-validator-" + [System.Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $tempDir -Force -ErrorAction Stop
        $destinationFile = Join-Path -Path $tempDir -ChildPath ([System.IO.Path]::GetFileName($BlobName))
        $null = Get-AzStorageBlobContent -Container $containerName -Blob $BlobName -Destination $destinationFile -Context $ctx -Force -ErrorAction Stop

        if (-not (Test-Path -LiteralPath $destinationFile)) {
            return @{ Found = $true; Valid = $false; Location = "$($account.StorageAccountName)/$containerName/$BlobName"; Payload = $null; Detail = 'Blob exists but was not downloaded to the expected temporary file.'; Account = $account }
        }
        $raw = Get-Content -LiteralPath $destinationFile -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return @{ Found = $true; Valid = $false; Location = "$($account.StorageAccountName)/$containerName/$BlobName"; Payload = $null; Detail = 'Blob JSON is empty.'; Account = $account }
        }
        try { $payload = $raw | ConvertFrom-Json -ErrorAction Stop }
        catch {
            return @{ Found = $true; Valid = $false; Location = "$($account.StorageAccountName)/$containerName/$BlobName"; Payload = $null; Detail = "Blob content is not valid JSON: $($_.Exception.Message)"; Account = $account }
        }
        if ($null -eq $payload) {
            return @{ Found = $true; Valid = $false; Location = "$($account.StorageAccountName)/$containerName/$BlobName"; Payload = $null; Detail = 'Blob content parsed to a null JSON payload.'; Account = $account }
        }
        return @{ Found = $true; Valid = $true; Location = "$($account.StorageAccountName)/$containerName/$BlobName"; Payload = $payload; Detail = 'Blob was downloaded and parsed as JSON from the resolved primary lab storage account.'; Account = $account }
    }
    catch {
        return @{ Found = $false; Valid = $false; Location = ''; Payload = $null; Detail = "Could not read blob '$BlobName' in container '$containerName' on resolved primary storage account '$($account.StorageAccountName)': $($_.Exception.Message)"; Account = $account }
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempDir) -and (Test-Path -LiteralPath $tempDir)) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-ResourceIdTextFromMapping {
    param([Parameter(Mandatory = $false)] $Mapping)
    if ($null -eq $Mapping) { return '' }
    try { return ($Mapping | ConvertTo-Json -Depth 20 -Compress -ErrorAction Stop) }
    catch { return [string]$Mapping }
}

function Test-ResourceGuardStandingAccess {
    param([Parameter(Mandatory = $true)] [string] $LearnerIdentity, [Parameter(Mandatory = $true)] $ResourceGuard)

    $badRoles = @('Contributor', 'Backup MUA Admin', 'Backup MUA Operator')
    $principalIds = New-Object System.Collections.Generic.List[string]
    $resolutionNotes = New-Object System.Collections.Generic.List[string]
    $assignments = @()
    $identity = $LearnerIdentity.Trim()

    try {
        $guidValue = [Guid]::Empty
        if ([Guid]::TryParse($identity, [ref]$guidValue)) {
            $principalIds.Add($identity)
            try {
                $userById = Get-AzADUser -ObjectId $identity -ErrorAction Stop
                if ($null -ne $userById -and -not [string]::IsNullOrWhiteSpace([string]$userById.Id) -and -not $principalIds.Contains([string]$userById.Id)) { $principalIds.Add([string]$userById.Id) }
            }
            catch { $resolutionNotes.Add("Microsoft Entra user lookup by object id was unavailable: $($_.Exception.Message)") }
        }
        else {
            try {
                $userByUpn = Get-AzADUser -UserPrincipalName $identity -ErrorAction Stop
                if ($null -ne $userByUpn -and -not [string]::IsNullOrWhiteSpace([string]$userByUpn.Id)) { $principalIds.Add([string]$userByUpn.Id) }
            }
            catch { $resolutionNotes.Add("Microsoft Entra user lookup by UPN was unavailable: $($_.Exception.Message)") }
        }

        # Enumerate WITHOUT -AtScope so assignments inherited from the resource group,
        # subscription, or management group are included. An inherited Contributor or
        # Backup MUA role collapses the separation boundary just as a direct one does.
        if ($principalIds.Count -gt 0) {
            foreach ($principalId in @($principalIds | Select-Object -Unique)) {
                $assignments += @(Get-AzRoleAssignment -ObjectId $principalId -Scope $ResourceGuard.ResourceId -ErrorAction Stop)
            }
        }
        else {
            $allInScope = @(Get-AzRoleAssignment -Scope $ResourceGuard.ResourceId -ErrorAction Stop)
            $assignments = @($allInScope | Where-Object { ([string]$_.SignInName -ieq $identity) -or ([string]$_.DisplayName -ieq $identity) -or ([string]$_.ObjectId -ieq $identity) })
            if ($assignments.Count -eq 0) {
                # Fail closed. Principal resolution failed, so absence of matching
                # assignments proves nothing about the learner's effective authority.
                return @{ Valid = $false; Unverifiable = $true; Detail = "UNVERIFIABLE: Resource Guard role-assignment enumeration succeeded, but directory principal resolution for learnerIdentity '$identity' failed, so no assignment could be attributed to the learner at or above Resource Guard scope '$($ResourceGuard.ResourceId)'. The separation boundary cannot be confirmed. Grant the validator identity Microsoft.Authorization/roleAssignments/read and Microsoft Entra user read, or supply learnerIdentity as an object id. $($resolutionNotes -join ' ')" }
            }
        }
    }
    catch {
        # Fail closed. An inspection failure is not evidence of a correct posture.
        return @{ Valid = $false; Unverifiable = $true; Detail = "UNVERIFIABLE: Resource Guard role assignments could not be inspected by the validator identity at scope '$($ResourceGuard.ResourceId)': $($_.Exception.Message). The standing-access requirement cannot be confirmed and this check does not pass by default. Grant the validator identity permission to read role assignments and role definitions, then re-run." }
    }

    # Reject by prohibited role NAME.
    $badAssignments = @($assignments | Where-Object { $_.RoleDefinitionName -in $badRoles })
    if ($badAssignments.Count -gt 0) {
        $badSummary = ($badAssignments | ForEach-Object { "$($_.RoleDefinitionName) at $($_.Scope)" }) -join '; '
        return @{ Valid = $false; Detail = "Learner identity '$identity' has prohibited standing Resource Guard authority: $badSummary. Remove standing Contributor, Backup MUA Admin, or Backup MUA Operator at or above the Resource Guard scope." }
    }

    # Reject by EFFECTIVE ACTIONS. A custom role can carry Resource Guard write
    # authority without using a prohibited role name, so inspect the underlying
    # role definitions rather than trusting display names alone.
    $guardWritePatterns = @(
        'Microsoft.DataProtection/subscriptions/resourceGroups/providers/resourceGuards/write',
        'Microsoft.DataProtection/subscriptions/resourceGroups/providers/resourceGuards/delete',
        'Microsoft.DataProtection/*/resourceGuards/write',
        'Microsoft.DataProtection/resourceGuards/write',
        'Microsoft.DataProtection/*',
        '*'
    )
    $effectiveWriteFindings = New-Object System.Collections.Generic.List[string]
    foreach ($assignment in $assignments) {
        $roleName = [string]$assignment.RoleDefinitionName
        $definition = $null
        try { $definition = Get-AzRoleDefinition -Name $roleName -ErrorAction Stop }
        catch {
            return @{ Valid = $false; Unverifiable = $true; Detail = "UNVERIFIABLE: Role definition '$roleName' assigned to learner identity '$identity' at '$($assignment.Scope)' could not be read, so its effective Resource Guard permissions cannot be evaluated: $($_.Exception.Message). This check does not pass by default." }
        }
        if ($null -eq $definition) { continue }

        $granted = @($definition.Actions) | Where-Object { $_ -in $guardWritePatterns }
        $denied = @($definition.NotActions) | Where-Object { $_ -in $guardWritePatterns }
        $stillGranted = @($granted | Where-Object { $_ -notin $denied })
        if ($stillGranted.Count -gt 0) {
            $effectiveWriteFindings.Add("role '$roleName' at '$($assignment.Scope)' grants $($stillGranted -join ', ')")
        }
    }
    if ($effectiveWriteFindings.Count -gt 0) {
        return @{ Valid = $false; Detail = "Learner identity '$identity' holds effective Resource Guard write authority despite carrying no prohibited role name: $($effectiveWriteFindings -join '; '). The separation boundary this lab demonstrates requires read and discovery access only. Remove the Resource Guard write operation, or add it to NotActions." }
    }

    $assignmentSummary = if ($assignments.Count -gt 0) { ($assignments | ForEach-Object { "$($_.RoleDefinitionName) at $($_.Scope)" }) -join '; ' } else { 'no role assignments attributable to the resolved learner principal at or above Resource Guard scope' }
    return @{ Valid = $true; Detail = "Resource Guard role-assignment inspection found $assignmentSummary; no prohibited role name and no effective Resource Guard write action was present for learnerIdentity '$identity', including inherited assignments. $($resolutionNotes -join ' ')" }
}

function Test-AuthorizationBoundaryEvidence {
    param([Parameter(Mandatory = $true)] $EvidenceBlob, [Parameter(Mandatory = $true)] [string] $ExpectedResourceGroup, [Parameter(Mandatory = $true)] [array] $Vaults, [Parameter(Mandatory = $true)] [array] $ResourceGuards)

    if (-not [bool]$EvidenceBlob.Found) { return @{ Valid = $false; Detail = $EvidenceBlob.Detail } }
    if (-not [bool]$EvidenceBlob.Valid) { return @{ Valid = $false; Detail = "Authorization-boundary evidence at '$($EvidenceBlob.Location)' is invalid: $($EvidenceBlob.Detail)" } }

    $payload = $EvidenceBlob.Payload
    $required = @('challenge', 'evidenceType', 'resourceGroup', 'vaultName', 'resourceGuardName', 'learnerIdentity', 'protectedOperation', 'authorizationResult', 'denialObserved', 'observedUtc', 'secretsIncluded', 'conceptualExplanation')
    $missing = @(Test-RequiredJsonProperties -Payload $payload -RequiredProperties $required)
    if ($missing.Count -gt 0) { return @{ Valid = $false; Detail = "Authorization-boundary evidence is missing required field(s): $($missing -join ', ')." } }

    $errors = New-Object System.Collections.Generic.List[string]
    $challenge = [string](Get-JsonPropertyValue -Payload $payload -Name 'challenge')
    $evidenceType = [string](Get-JsonPropertyValue -Payload $payload -Name 'evidenceType')
    $markerRg = [string](Get-JsonPropertyValue -Payload $payload -Name 'resourceGroup')
    $vaultName = [string](Get-JsonPropertyValue -Payload $payload -Name 'vaultName')
    $guardName = [string](Get-JsonPropertyValue -Payload $payload -Name 'resourceGuardName')
    $learnerIdentity = [string](Get-JsonPropertyValue -Payload $payload -Name 'learnerIdentity')
    $protectedOperation = [string](Get-JsonPropertyValue -Payload $payload -Name 'protectedOperation')
    $authorizationResult = [string](Get-JsonPropertyValue -Payload $payload -Name 'authorizationResult')
    $denialObserved = Get-JsonPropertyValue -Payload $payload -Name 'denialObserved'
    $observedUtc = Get-JsonPropertyValue -Payload $payload -Name 'observedUtc'
    $secretsIncluded = Get-JsonPropertyValue -Payload $payload -Name 'secretsIncluded'
    $conceptualExplanation = Get-JsonPropertyValue -Payload $payload -Name 'conceptualExplanation'

    if ($challenge -cne '03') { $errors.Add("challenge must be exactly '03'") }
    if ($evidenceType -cne 'authorization-boundary') { $errors.Add("evidenceType must be exactly 'authorization-boundary'") }
    if ($markerRg -ne $ExpectedResourceGroup) { $errors.Add("resourceGroup must match resolved RG '$ExpectedResourceGroup'") }
    if ([string]::IsNullOrWhiteSpace($vaultName)) { $errors.Add('vaultName must be non-empty') }
    if ([string]::IsNullOrWhiteSpace($guardName)) { $errors.Add('resourceGuardName must be non-empty') }
    if ([string]::IsNullOrWhiteSpace($learnerIdentity)) { $errors.Add('learnerIdentity must be non-empty') }
    # protectedOperation must name an operation that Resource Guard actually protects.
    # A non-empty free-text string would let a fabricated marker satisfy the central
    # Challenge 3 outcome. List per Microsoft Learn "Multiuser authorization using
    # Resource Guard" — critical operations.
    $criticalOperations = @(
        'DisableSoftDelete',
        'DisableMUAProtection',
        'ModifyBackupPolicy',
        'ModifyProtection',
        'StopProtectionWithDeleteData',
        'DeleteBackupData',
        'ChangeMARSSecurityPIN',
        'GetSecurityPIN'
    )
    if ([string]::IsNullOrWhiteSpace($protectedOperation)) { $errors.Add('protectedOperation must be non-empty') }
    elseif ($protectedOperation -notin $criticalOperations) {
        $errors.Add("protectedOperation '$protectedOperation' is not a Resource Guard critical operation. It must be one of: $($criticalOperations -join ', '). See https://learn.microsoft.com/azure/backup/multi-user-authorization-concept#critical-operations")
    }
    if ($authorizationResult -cne 'Denied') { $errors.Add("authorizationResult must be exactly 'Denied'") }
    if ($denialObserved -isnot [bool] -or -not [bool]$denialObserved) { $errors.Add('denialObserved must be Boolean true') }
    if (-not (Test-UtcTimestamp -Value $observedUtc)) { $errors.Add('observedUtc must be a parseable UTC timestamp') }
    if ($secretsIncluded -isnot [bool] -or [bool]$secretsIncluded) { $errors.Add('secretsIncluded must be Boolean false') }

    if ($null -eq $conceptualExplanation -or $null -eq $conceptualExplanation.PSObject -or $null -eq $conceptualExplanation.PSObject.Properties) { $errors.Add('conceptualExplanation must exist as a JSON object') }
    else {
        $conceptFields = @('separateApproverIdentity', 'backupMuaOperatorEligibleAssignment', 'pimActivationWithApproval', 'timeBoundActivation', 'standingAccessRisk', 'ransomwarePreventionValue', 'notPerformedReason', 'requirementsToPerform')
        foreach ($fieldName in $conceptFields) {
            if (-not (Test-NonEmptyEvidenceField -Payload $conceptualExplanation -Name $fieldName)) { $errors.Add("conceptualExplanation.$fieldName must exist and be non-empty") }
        }
    }

    $matchedVault = $null
    if (-not [string]::IsNullOrWhiteSpace($vaultName)) {
        $matchedVault = $Vaults | Where-Object { $_.Name -eq $vaultName -and $_.ResourceGroupName -eq $ExpectedResourceGroup } | Select-Object -First 1
        if ($null -eq $matchedVault) { $errors.Add("vaultName '$vaultName' must match a deployed Recovery Services vault in RG '$ExpectedResourceGroup'") }
    }

    $matchedGuard = $null
    if (-not [string]::IsNullOrWhiteSpace($guardName)) {
        $matchedGuard = $ResourceGuards | Where-Object { $_.Name -eq $guardName -and $_.ResourceGroupName -eq $ExpectedResourceGroup } | Select-Object -First 1
        if ($null -eq $matchedGuard) { $errors.Add("resourceGuardName '$guardName' must match a deployed Microsoft.DataProtection/resourceGuards resource in RG '$ExpectedResourceGroup'") }
    }

    $mappingDetail = 'Vault-to-Resource Guard mapping was not evaluated because the named vault or guard was not resolved.'
    $mappingOk = $false
    if ($null -ne $matchedVault -and $null -ne $matchedGuard) {
        try {
            $mappings = @(Get-AzRecoveryServicesResourceGuardMapping -VaultId $matchedVault.ID -ErrorAction Stop)
            $mappingText = (($mappings | ForEach-Object { Get-ResourceIdTextFromMapping -Mapping $_ }) -join ' ')
            $guardIdPattern = [regex]::Escape([string]$matchedGuard.ResourceId)
            $guardNamePattern = "/resourceGuards/$([regex]::Escape($matchedGuard.Name))"
            $mappingOk = ($mappingText -match $guardIdPattern) -or ($mappingText -match $guardNamePattern)
            if ($mappingOk) { $mappingDetail = "Recovery Services vault '$vaultName' has a Resource Guard mapping that references '$guardName'." }
            else {
                $mappingDetail = "Recovery Services vault '$vaultName' mapping did not reference Resource Guard '$guardName'. Mapping payload: $mappingText"
                $errors.Add($mappingDetail)
            }
        }
        catch {
            $mappingDetail = "Could not read Resource Guard mapping for Recovery Services vault '$vaultName': $($_.Exception.Message)"
            $errors.Add($mappingDetail)
        }
    }

    $roleAccessValidation = @{ Valid = $true; Detail = 'Resource Guard role-assignment inspection was skipped because prerequisite marker or resource validation failed.' }
    if ($errors.Count -eq 0 -and $mappingOk) {
        $roleAccessValidation = Test-ResourceGuardStandingAccess -LearnerIdentity $learnerIdentity -ResourceGuard $matchedGuard
        if (-not [bool]$roleAccessValidation.Valid) { $errors.Add($roleAccessValidation.Detail) }
    }

    # Corroborate the claimed denial against Azure control-plane telemetry rather than
    # trusting the learner-authored authorizationResult and denialObserved fields.
    # Where telemetry cannot attribute the denial, the claim is classified explicitly
    # as human-reviewed rather than presented as server-validated.
    $denialCorroboration = 'Denial corroboration was not attempted because prerequisite validation failed.'
    $denialCorroborated = $false
    if ($errors.Count -eq 0 -and $null -ne $matchedVault) {
        try {
            $observedTime = [datetime]::MinValue
            $null = [datetime]::TryParse([string]$observedUtc, [ref]$observedTime)
            $windowStart = if ($observedTime -gt [datetime]::MinValue) { $observedTime.ToUniversalTime().AddHours(-2) } else { (Get-Date).ToUniversalTime().AddHours(-6) }

            $activityEvents = @(Get-AzActivityLog -ResourceId $matchedVault.ID -StartTime $windowStart -ErrorAction Stop)
            $failedEvents = @($activityEvents | Where-Object {
                    $status = [string]$_.Status.Value
                    $sub = [string]$_.SubStatus.Value
                    ($status -match 'Fail') -or ($sub -match 'Forbidden') -or ($sub -match 'Unauthorized') -or ([string]$_.ResultType -match 'Fail')
                })

            if ($failedEvents.Count -gt 0) {
                $denialCorroborated = $true
                $sample = ($failedEvents | Select-Object -First 3 | ForEach-Object { "$([string]$_.OperationName.Value) ($([string]$_.SubStatus.Value)) at $($_.EventTimestamp)" }) -join '; '
                $denialCorroboration = "Denial corroborated by $($failedEvents.Count) failed control-plane event(s) on vault '$vaultName' since $($windowStart.ToString('u')): $sample"
            }
            else {
                $denialCorroboration = "HUMAN-REVIEWED: No failed control-plane event was found on vault '$vaultName' since $($windowStart.ToString('u')) to corroborate the claimed '$protectedOperation' denial. Activity Log ingestion can lag, and Resource Guard denials are not always surfaced as attributable failed events. The declared denial is therefore recorded as learner-attested and requires human review; it is not server-validated."
            }
        }
        catch {
            $denialCorroboration = "HUMAN-REVIEWED: Activity Log could not be queried for vault '$vaultName' to corroborate the claimed denial: $($_.Exception.Message). The declared denial is recorded as learner-attested and requires human review; it is not server-validated."
        }
    }

    if ($errors.Count -gt 0) { return @{ Valid = $false; Detail = "Authorization-boundary evidence schema/semantics failed: $($errors -join '; '). $mappingDetail $($roleAccessValidation.Detail) $denialCorroboration" } }
    return @{ Valid = $true; DenialCorroborated = $denialCorroborated; Detail = "Authorization-boundary evidence at '$($EvidenceBlob.Location)' is valid for learnerIdentity '$learnerIdentity', protectedOperation '$protectedOperation', vault '$vaultName', and Resource Guard '$guardName'. $mappingDetail $($roleAccessValidation.Detail) $denialCorroboration" }
}

function Test-ManualHuntingEvidence {
    param([Parameter(Mandatory = $true)] $EvidenceBlob, [Parameter(Mandatory = $true)] [string] $ExpectedResourceGroup, [Parameter(Mandatory = $true)] [string] $ExpectedStorageAccount)

    if (-not [bool]$EvidenceBlob.Found) { return @{ Valid = $false; Detail = $EvidenceBlob.Detail } }
    if (-not [bool]$EvidenceBlob.Valid) { return @{ Valid = $false; Detail = "Manual hunting evidence at '$($EvidenceBlob.Location)' is invalid: $($EvidenceBlob.Detail)" } }

    $payload = $EvidenceBlob.Payload
    $required = @('challenge', 'evidenceType', 'defenderAlertStatus', 'reason', 'resourceGroup', 'storageAccount', 'containera-unprotected', 'containerb-protectme', 'defenderForStorageEnabled', 'logAnalyticsWorkspacePresent', 'huntingPerformed', 'secretsIncluded', 'recordedUtc')
    $missing = @(Test-RequiredJsonProperties -Payload $payload -RequiredProperties $required)
    if ($missing.Count -gt 0) { return @{ Valid = $false; Detail = "Manual hunting evidence is missing required field(s): $($missing -join ', ')." } }

    $errors = New-Object System.Collections.Generic.List[string]
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'challenge') -ne '05') { $errors.Add("challenge must be '05'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'evidenceType') -ne 'manual-hunting-pending') { $errors.Add("evidenceType must be 'manual-hunting-pending'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'defenderAlertStatus') -ne 'pending-or-not-generated') { $errors.Add("defenderAlertStatus must be 'pending-or-not-generated'") }
    if ([string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Payload $payload -Name 'reason'))) { $errors.Add('reason must be non-empty') }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'resourceGroup') -ne $ExpectedResourceGroup) { $errors.Add("resourceGroup must match '$ExpectedResourceGroup'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'storageAccount') -ne $ExpectedStorageAccount) { $errors.Add("storageAccount must match '$ExpectedStorageAccount'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'containera-unprotected') -ne 'containera-unprotected') { $errors.Add("containera-unprotected must equal 'containera-unprotected'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'containerb-protectme') -ne 'containerb-protectme') { $errors.Add("containerb-protectme must equal 'containerb-protectme'") }
    if (-not (Test-TruthyValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'defenderForStorageEnabled'))) { $errors.Add('defenderForStorageEnabled must be truthy') }
    if (-not (Test-BooleanLikeValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'logAnalyticsWorkspacePresent'))) { $errors.Add('logAnalyticsWorkspacePresent must be a Boolean or Boolean-like value') }
    if (-not (Test-FalseBooleanValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'secretsIncluded'))) { $errors.Add('secretsIncluded must be false') }
    if (-not (Test-UtcTimestamp -Value (Get-JsonPropertyValue -Payload $payload -Name 'recordedUtc'))) { $errors.Add('recordedUtc must be a parseable UTC timestamp') }

    $huntingValues = @(ConvertTo-ArrayValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'huntingPerformed')) | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($huntingValues.Count -eq 0) { $errors.Add('huntingPerformed must contain at least one non-empty operational hunting source') }
    else {
        $joined = ($huntingValues -join ' | ').ToLowerInvariant()
        if (-not ($joined -match 'defender|diagnostic|storagebloblogs|container state|attack-script|attack script|activity log|platform|storage state|telemetry')) { $errors.Add('huntingPerformed must name operational hunt sources such as Defender configuration, diagnostic settings, StorageBlobLogs, Activity Log, container state, platform telemetry, or attack-script output') }
    }

    if ($errors.Count -gt 0) { return @{ Valid = $false; Detail = "Manual hunting evidence schema/semantics failed: $($errors -join '; ')." } }
    return @{ Valid = $true; Detail = "Manual hunting evidence at '$($EvidenceBlob.Location)' matches the documented Challenge 5 pending-alert schema." }
}

function Test-KeyRotationEvidence {
    param([Parameter(Mandatory = $true)] $EvidenceBlob, [Parameter(Mandatory = $true)] [string] $ExpectedResourceGroup, [Parameter(Mandatory = $true)] [string] $ExpectedStorageAccount)

    if (-not [bool]$EvidenceBlob.Found) { return @{ Valid = $false; Detail = $EvidenceBlob.Detail } }
    if (-not [bool]$EvidenceBlob.Valid) { return @{ Valid = $false; Detail = "Key rotation evidence at '$($EvidenceBlob.Location)' is invalid: $($EvidenceBlob.Detail)" } }

    $payload = $EvidenceBlob.Payload
    $required = @('challenge', 'evidenceType', 'resourceGroup', 'storageAccount', 'rotatedPrimaryKey', 'oldPrimaryKeyResult', 'newPrimaryKeyResult', 'secondaryRotationAttempted', 'verifiedContainerListingScope', 'secretsIncluded', 'recordedUtc')
    $missing = @(Test-RequiredJsonProperties -Payload $payload -RequiredProperties $required)
    if ($missing.Count -gt 0) { return @{ Valid = $false; Detail = "Key rotation evidence is missing required field(s): $($missing -join ', ')." } }

    $errors = New-Object System.Collections.Generic.List[string]
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'challenge') -ne '05') { $errors.Add("challenge must be '05'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'evidenceType') -ne 'key-rotation-verified') { $errors.Add("evidenceType must be 'key-rotation-verified'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'resourceGroup') -ne $ExpectedResourceGroup) { $errors.Add("resourceGroup must match '$ExpectedResourceGroup'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'storageAccount') -ne $ExpectedStorageAccount) { $errors.Add("storageAccount must match '$ExpectedStorageAccount'") }
    if (-not (Test-TruthyValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'rotatedPrimaryKey'))) { $errors.Add('rotatedPrimaryKey must be true') }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'oldPrimaryKeyResult') -ne 'old-key-rejected') { $errors.Add("oldPrimaryKeyResult must be 'old-key-rejected'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'newPrimaryKeyResult') -ne 'new-key-authorized') { $errors.Add("newPrimaryKeyResult must be 'new-key-authorized'") }
    if ((Get-JsonPropertyValue -Payload $payload -Name 'secondaryRotationAttempted') -isnot [bool]) { $errors.Add('secondaryRotationAttempted must be a Boolean') }
    if ([string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Payload $payload -Name 'verifiedContainerListingScope'))) { $errors.Add('verifiedContainerListingScope must be non-empty') }
    if (-not (Test-FalseBooleanValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'secretsIncluded'))) { $errors.Add('secretsIncluded must be false') }
    if (-not (Test-UtcTimestamp -Value (Get-JsonPropertyValue -Payload $payload -Name 'recordedUtc'))) { $errors.Add('recordedUtc must be a parseable UTC timestamp') }

    if ($errors.Count -gt 0) { return @{ Valid = $false; Detail = "Key rotation evidence schema/semantics failed: $($errors -join '; ')." } }
    return @{ Valid = $true; Detail = "Key rotation evidence at '$($EvidenceBlob.Location)' matches the documented Challenge 5 schema." }
}

function Test-RestoreChecksumEvidence {
    param([Parameter(Mandatory = $true)] $EvidenceBlob)

    if (-not [bool]$EvidenceBlob.Found) { return @{ Valid = $false; Detail = $EvidenceBlob.Detail } }
    if (-not [bool]$EvidenceBlob.Valid) { return @{ Valid = $false; Detail = "Restore checksum evidence at '$($EvidenceBlob.Location)' is invalid: $($EvidenceBlob.Detail)" } }

    $payload = $EvidenceBlob.Payload
    $required = @('challenge', 'validation', 'status', 'checkedAtUtc', 'manifestPath', 'seedRoot', 'filesPassed', 'filesFailed', 'results')
    $missing = @(Test-RequiredJsonProperties -Payload $payload -RequiredProperties $required)
    if ($missing.Count -gt 0) { return @{ Valid = $false; Detail = "Restore checksum evidence is missing required field(s): $($missing -join ', ')." } }

    $errors = New-Object System.Collections.Generic.List[string]
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'challenge') -ne 'Challenge 6') { $errors.Add("challenge must be 'Challenge 6'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'validation') -ne 'Restore checksum comparison') { $errors.Add("validation must be 'Restore checksum comparison'") }
    if ([string](Get-JsonPropertyValue -Payload $payload -Name 'status') -ne 'Succeeded') { $errors.Add("status must be exactly 'Succeeded'") }
    if (-not (Test-UtcTimestamp -Value (Get-JsonPropertyValue -Payload $payload -Name 'checkedAtUtc'))) { $errors.Add('checkedAtUtc must be a parseable UTC timestamp') }
    if ([string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Payload $payload -Name 'manifestPath'))) { $errors.Add('manifestPath must be non-empty') }
    if ([string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -Payload $payload -Name 'seedRoot'))) { $errors.Add('seedRoot must be non-empty') }

    $filesPassed = 0
    $filesFailed = -1
    if (-not [int]::TryParse([string](Get-JsonPropertyValue -Payload $payload -Name 'filesPassed'), [ref]$filesPassed)) { $errors.Add('filesPassed must be an integer') }
    if (-not [int]::TryParse([string](Get-JsonPropertyValue -Payload $payload -Name 'filesFailed'), [ref]$filesFailed)) { $errors.Add('filesFailed must be an integer') }
    if ($filesPassed -le 0) { $errors.Add('filesPassed must be greater than 0') }
    if ($filesFailed -ne 0) { $errors.Add('filesFailed must equal 0') }

    $results = @(ConvertTo-ArrayValue -Value (Get-JsonPropertyValue -Payload $payload -Name 'results'))
    if ($results.Count -eq 0) { $errors.Add('results must contain at least one file result') }
    else {
        $passedRows = @($results | Where-Object { [string](Get-JsonPropertyValue -Payload $_ -Name 'Result') -eq 'Passed' -or [string](Get-JsonPropertyValue -Payload $_ -Name 'result') -eq 'Passed' })
        $failedRows = @($results | Where-Object { [string](Get-JsonPropertyValue -Payload $_ -Name 'Result') -eq 'Failed' -or [string](Get-JsonPropertyValue -Payload $_ -Name 'result') -eq 'Failed' })
        if ($passedRows.Count -ne $filesPassed) { $errors.Add("results passed count '$($passedRows.Count)' must match filesPassed '$filesPassed'") }
        if ($failedRows.Count -ne 0) { $errors.Add('results must not contain failed file entries') }
        if ($results.Count -ne $filesPassed) { $errors.Add("results total count '$($results.Count)' must match filesPassed '$filesPassed' when filesFailed is 0") }
    }

    if ($errors.Count -gt 0) { return @{ Valid = $false; Detail = "Restore checksum evidence schema/semantics failed: $($errors -join '; ')." } }
    return @{ Valid = $true; Detail = "Restore checksum evidence at '$($EvidenceBlob.Location)' proves a successful checksum comparison for $filesPassed restored file(s)." }
}

function Test-CurrentStorageKeyAccess {
    param([Parameter(Mandatory = $true)] $StorageAccount)

    try {
        $keys = Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction Stop
        $key = ($keys | Where-Object { $_.KeyName -eq 'key1' } | Select-Object -First 1).Value
        if ([string]::IsNullOrWhiteSpace($key)) { $key = ($keys | Select-Object -First 1).Value }
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $key -ErrorAction Stop
        foreach ($containerName in $canonicalContainerNames) {
            $container = Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction Stop
            if ($null -eq $container) { throw "container '$containerName' was not returned" }
        }
        return @{ Succeeded = $true; Account = $StorageAccount.StorageAccountName }
    }
    catch {
        return @{ Succeeded = $false; Account = $StorageAccount.StorageAccountName; Detail = $_.Exception.Message }
    }
}

function Get-DefenderForStorageState {
    param([Parameter(Mandatory = $true)] $StorageAccount)

    $resourceId = "$($StorageAccount.Id)/providers/Microsoft.Security/defenderForStorageSettings/current"
    $source = 'Microsoft.Security/defenderForStorageSettings/current@2025-01-01'
    try {
        $setting = Get-AzResource -ResourceId $resourceId -ApiVersion '2025-01-01' -ExpandProperties -ErrorAction Stop
        $enabled = $false
        if ($null -ne $setting -and $null -ne $setting.Properties) { $enabled = [bool]$setting.Properties.isEnabled }
        return @{ Readable = $true; Enabled = $enabled; Source = $source; ResourceId = $resourceId; Detail = "$source read from '$resourceId' with properties.isEnabled=$enabled" }
    }
    catch {
        return @{ Readable = $false; Enabled = $false; Source = $source; ResourceId = $resourceId; Detail = "$source could not be read from '$resourceId': $($_.Exception.Message)" }
    }
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop

        $details = New-Object System.Collections.Generic.List[string]
        $rg = Resolve-ExactLabResourceGroup -DeploymentId $DID
        $null = Get-AzResourceGroup -Name $rg -ErrorAction Stop
        $resolvedStorage = Resolve-ExactLabStorageAccount -ResourceGroupName $rg
        $primaryStorageAccount = $resolvedStorage.StorageAccount
        $primaryStorageName = [string]$primaryStorageAccount.StorageAccountName
        $details.Add("Primary storage: Resolve-ExactLabStorageAccount selected '$primaryStorageName' because it is the only account in RG '$rg' containing all canonical containers '$($canonicalContainerNames -join ', ')'.")

        $vaults = @(Get-AzRecoveryServicesVault -ResourceGroupName $rg -ErrorAction SilentlyContinue)
        $resourceGuards = @(Get-AzResource -ResourceGroupName $rg -ResourceType 'Microsoft.DataProtection/resourceGuards' -ErrorAction SilentlyContinue)

        # 1. Challenge 3 authorization boundary evidence and Resource Guard separation validation.
        $authorizationBoundaryBlob = Test-EvidenceBlob -ResolvedStorageAccount $resolvedStorage -BlobName 'challenge-03/authorization-boundary.json'
        $authorizationBoundaryValidation = Test-AuthorizationBoundaryEvidence -EvidenceBlob $authorizationBoundaryBlob -ExpectedResourceGroup $rg -Vaults $vaults -ResourceGuards $resourceGuards
        $authorizationBoundaryOk = [bool]$authorizationBoundaryValidation.Valid
        if ($authorizationBoundaryOk) { $details.Add("Authorization boundary: $($authorizationBoundaryValidation.Detail)") }
        else { $details.Add("Authorization boundary incomplete: upload a valid nonsecret lab-evidence/challenge-03/authorization-boundary.json marker that records a Denied protected-operation attempt, complete conceptual MUA explanation, deployed vault/Resource Guard names, and no standing prohibited Resource Guard roles for the learner. $($authorizationBoundaryValidation.Detail)") }

        # 2. Challenge 5 investigation evidence: pass if an actual Defender for Storage alert is visible, or if the approved pending-alert path is documented and the current Defender for Storage resource is readable and enabled.
        $alertRows = @()
        $alertQueryError = $null
        try {
            $alertQuery = @"
securityresources
| where type =~ 'microsoft.security/locations/alerts'
| extend props = tostring(properties)
| where props contains '$primaryStorageName' or props contains '$($primaryStorageAccount.Id)' or props contains '$rg'
| project name, alertType=tostring(properties.AlertType), displayName=tostring(properties.AlertDisplayName), status=tostring(properties.Status), severity=tostring(properties.Severity), timeGenerated=todatetime(properties.TimeGenerated), resourceIdentifiers=tostring(properties.ResourceIdentifiers)
| order by timeGenerated desc
"@
            $argResult = Search-AzGraph -Query $alertQuery -Subscription $sub -First 20 -ErrorAction Stop
            if ($null -ne $argResult.Data) { $alertRows = @($argResult.Data) } else { $alertRows = @($argResult) }
        }
        catch {
            $alertQueryError = $_.Exception.Message
            $alertRows = @()
        }

        $actualDefenderAlertFound = $alertRows.Count -gt 0
        $defenderState = Get-DefenderForStorageState -StorageAccount $primaryStorageAccount
        $defenderForStorageReadable = [bool]$defenderState.Readable
        $defenderForStorageEnabled = [bool]$defenderState.Enabled

        $manualHuntingBlob = Test-EvidenceBlob -ResolvedStorageAccount $resolvedStorage -BlobName 'challenge-05/manual-hunting-pending.json'
        $manualHuntingValidation = Test-ManualHuntingEvidence -EvidenceBlob $manualHuntingBlob -ExpectedResourceGroup $rg -ExpectedStorageAccount $primaryStorageName
        $investigationOk = $actualDefenderAlertFound -or ($defenderForStorageEnabled -and [bool]$manualHuntingValidation.Valid)

        if ($actualDefenderAlertFound) {
            $firstAlert = $alertRows | Select-Object -First 1
            $details.Add("Investigation: Defender for Storage alert evidence found for resolved primary storage account '$primaryStorageName'. Alert '$($firstAlert.displayName)' / type '$($firstAlert.alertType)' status '$($firstAlert.status)'.")
        }
        elseif ($defenderForStorageEnabled -and [bool]$manualHuntingValidation.Valid) {
            $details.Add("Investigation: Defender for Storage setting '$($defenderState.Source)' is readable and properties.isEnabled is true for resolved primary storage account '$primaryStorageName', and approved manual-hunting pending evidence is valid. $($manualHuntingValidation.Detail)")
        }
        elseif ($defenderForStorageReadable) {
            $details.Add("Investigation incomplete: no Defender for Storage alert was found for resolved primary storage account '$primaryStorageName'. Defender for Storage state was readable as '$($defenderState.Detail)', but the pending-alert path requires properties.isEnabled true on Microsoft.Security/defenderForStorageSettings/current@2025-01-01 and valid lab-evidence/challenge-05/manual-hunting-pending.json with defenderForStorageEnabled truthy. $($manualHuntingValidation.Detail)")
        }
        else {
            $alertNote = if ($null -ne $alertQueryError) { " Alert query note: $alertQueryError" } else { '' }
            $details.Add("Investigation incomplete: no Defender for Storage alert was found for resolved primary storage account '$primaryStorageName' and the pending-alert path cannot pass because Microsoft.Security/defenderForStorageSettings/current@2025-01-01 was not readable with properties.isEnabled true. Defender for Storage read detail: $($defenderState.Detail). $($manualHuntingValidation.Detail)$alertNote")
        }

        # 3. Storage account key rotation: require a real Activity Log key-regeneration event on the resolved primary account, valid learner verification marker, and current-key access.
        $startTime = (Get-Date).AddDays(-7).ToUniversalTime()
        $endTime = (Get-Date).AddMinutes(5).ToUniversalTime()
        $keyRotationEvents = @()
        try {
            $events = @(Get-AzActivityLog -ResourceId $primaryStorageAccount.Id -StartTime $startTime -EndTime $endTime -DetailedOutput -MaxRecord 1000 -ErrorAction Stop)
            $keyRotationEvents = @($events | Where-Object {
                $operationValue = ''
                if ($null -ne $_.OperationName) { $operationValue = "$($_.OperationName.Value) $($_.OperationName.LocalizedValue)" }
                $statusValue = ''
                if ($null -ne $_.Status) { $statusValue = "$($_.Status.Value) $($_.Status.LocalizedValue)" }
                ($operationValue -match 'regenerateKey/action|Regenerate Storage Account Keys|Regenerate Storage Account Key') -and ($statusValue -match 'Succeeded|Success|Accepted')
            })
        }
        catch {
            $details.Add("Key rotation note: Activity Log query for resolved primary storage account '$primaryStorageName' returned an error: $($_.Exception.Message)")
        }

        $keyRotationBlob = Test-EvidenceBlob -ResolvedStorageAccount $resolvedStorage -BlobName 'challenge-05/key-rotation-verified.json'
        $keyRotationValidation = Test-KeyRotationEvidence -EvidenceBlob $keyRotationBlob -ExpectedResourceGroup $rg -ExpectedStorageAccount $primaryStorageName
        $currentStorageAccess = Test-CurrentStorageKeyAccess -StorageAccount $primaryStorageAccount
        $keyRotationOk = ($keyRotationEvents.Count -gt 0) -and [bool]$keyRotationValidation.Valid -and [bool]$currentStorageAccess.Succeeded

        if ($keyRotationOk) {
            $latestRotation = $keyRotationEvents | Sort-Object EventTimestamp -Descending | Select-Object -First 1
            $details.Add("Key rotation: Activity Log shows a successful key regeneration for resolved primary storage account '$primaryStorageName' at '$($latestRotation.EventTimestamp)', key-rotation JSON is valid at '$($keyRotationBlob.Location)', and current key access was verified against the same account.")
        }
        elseif ($keyRotationEvents.Count -eq 0) { $details.Add("Key rotation incomplete: no successful Activity Log event for storage account key regeneration was found in the last 7 days for resolved primary storage account '$primaryStorageName'.") }
        elseif (-not [bool]$keyRotationValidation.Valid) { $details.Add("Key rotation incomplete: a key-regeneration Activity Log event exists for resolved primary storage account '$primaryStorageName', but lab-evidence/challenge-05/key-rotation-verified.json is missing or invalid for that same account. $($keyRotationValidation.Detail)") }
        else { $details.Add("Key rotation partial: key-regeneration evidence and valid JSON evidence exist for '$primaryStorageName', but the validator could not list the canonical containers with the current storage account key. $($currentStorageAccess.Detail)") }

        # 4. Recovery point and restore completion from the same-session VM backup.
        $recoveryPointCount = 0
        $backupItemNames = @()
        foreach ($vault in $vaults) {
            try {
                $items = @(Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $vault.ID -ErrorAction Stop)
                foreach ($item in $items) {
                    $backupItemNames += $item.Name
                    $points = @(Get-AzRecoveryServicesBackupRecoveryPoint -Item $item -StartDate (Get-Date).AddDays(-3).ToUniversalTime() -EndDate (Get-Date).ToUniversalTime() -VaultId $vault.ID -ErrorAction SilentlyContinue)
                    $recoveryPointCount += $points.Count
                }
            }
            catch {
                # Continue with restore-job checks so asynchronous vault indexing does not hide useful partial status.
            }
        }
        $sameSessionRecoveryPointOk = $recoveryPointCount -ge 1

        $completedRestoreJobs = @()
        $inProgressRestoreJobs = @()
        foreach ($vault in $vaults) {
            try {
                $restoreJobs = @(Get-AzRecoveryServicesBackupJob -VaultId $vault.ID -Operation Restore -From (Get-Date).AddDays(-3).ToUniversalTime() -To (Get-Date).ToUniversalTime() -BackupManagementType AzureVM -ErrorAction Stop)
                $completedRestoreJobs += @($restoreJobs | Where-Object { $_.Status -in @('Completed', 'CompletedWithWarnings') })
                $inProgressRestoreJobs += @($restoreJobs | Where-Object { $_.Status -in @('InProgress', 'Cancelling') })
            }
            catch {
                # Continue; the failure is reflected in the aggregate restore status below.
            }
        }
        $restoreOk = $completedRestoreJobs.Count -gt 0

        if ($sameSessionRecoveryPointOk) { $details.Add("Recovery point: found $recoveryPointCount Azure VM recovery point(s) from the current lab window for backup item(s): $($backupItemNames -join ', ').") }
        else { $details.Add('Recovery point incomplete: no Azure VM recovery point was found in the last 3 days in the Recovery Services vault.') }

        if ($restoreOk) {
            $latestRestore = $completedRestoreJobs | Sort-Object EndTime -Descending | Select-Object -First 1
            $details.Add("Restore: Azure VM restore job '$($latestRestore.JobId)' completed with status '$($latestRestore.Status)' for workload '$($latestRestore.WorkloadName)'.")
        }
        elseif ($inProgressRestoreJobs.Count -gt 0) {
            $job = $inProgressRestoreJobs | Sort-Object StartTime -Descending | Select-Object -First 1
            $details.Add("Restore partial: restore job '$($job.JobId)' is still '$($job.Status)'. VM restore can take meaningful time; wait for completion before validating checksum evidence.")
        }
        else { $details.Add('Restore incomplete: no completed Azure VM restore job was found in the last 3 days for the lab vault.') }

        # 5. Checksum/integrity completion marker. This must be cloud-visible because validators run server-side and must validate the JSON summary, not existence only.
        $checksumBlob = Test-EvidenceBlob -ResolvedStorageAccount $resolvedStorage -BlobName 'challenge-06/restore-checksum-complete.json'
        $checksumValidation = Test-RestoreChecksumEvidence -EvidenceBlob $checksumBlob
        $checksumOk = [bool]$checksumValidation.Valid
        if ($checksumOk) { $details.Add("Checksum: $($checksumValidation.Detail)") }
        else { $details.Add("Checksum incomplete: upload a valid lab-evidence/challenge-06/restore-checksum-complete.json generated by the Challenge 6 checksum comparison after validating restored files. $($checksumValidation.Detail)") }

        $found = $authorizationBoundaryOk -and $investigationOk -and $keyRotationOk -and $sameSessionRecoveryPointOk -and $restoreOk -and $checksumOk
        $summary = $details -join ' '

        if ($found) {
            $message = @{ Status = 'Succeeded'; Message = "Recovery and investigation completion passed in RG '$rg' using resolved primary storage account '$primaryStorageName', including Challenge 3 one-identity authorization-boundary validation. $summary" } | ConvertTo-Json
        }
        else {
            $message = @{ Status = 'Failed'; Message = "Recovery and investigation completion incomplete in RG '$rg' using resolved primary storage account '$primaryStorageName'. $summary" } | ConvertTo-Json
        }
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })

        if (-not $found -and $count -lt 3) { Start-Sleep -Seconds 10 }
    }
    catch {
        $message = @{ Status = 'Failed'; Message = "Error during Recovery and investigation completion check. Attempt $count of 3. Error: $($_.Exception.Message)" } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs
# always sees a structured result.
if (-not $found) {
    $rgDetail = if ([string]::IsNullOrWhiteSpace($rg)) { "a single resource group resolved by exact deploymentId/DeploymentID tags for deployment '$DID'" } else { "RG '$rg'" }
    $message = @{
        Status  = 'Failed'
        Message = "Recovery and investigation completion was not fully validated in $rgDetail after 3 attempts. Required evidence: exactly one primary lab storage account in the resolved RG containing all three canonical containers '$($canonicalContainerNames -join ', ')' as determined by Resolve-ExactLabStorageAccount; valid Challenge 3 authorization-boundary marker lab-evidence/challenge-03/authorization-boundary.json with Denied result, denialObserved true, secretsIncluded false, complete conceptualExplanation fields, deployed Recovery Services vault and Resource Guard mapping, and no prohibited standing Resource Guard role assignment for the learner when assignments are inspectable; Defender for Storage alert or valid pending-alert marker lab-evidence/challenge-05/manual-hunting-pending.json with defenderForStorageEnabled truthy and a readable enabled Microsoft.Security/defenderForStorageSettings/current@2025-01-01 state on the resolved primary account; a real Activity Log storage key-regeneration event on the resolved primary account plus valid lab-evidence/challenge-05/key-rotation-verified.json and current-key access; a completed Azure VM restore job from a same-session recovery point; and valid successful checksum JSON at lab-evidence/challenge-06/restore-checksum-complete.json."
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $message })
}
