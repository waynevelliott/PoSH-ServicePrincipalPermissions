<#
$MaximumFunctionCount = 32768
Import-Module -Name microsoft.graph

if (!(Get-MgContext)) {Connect-MgGraph -Environment Global -NoWelcome -TenantId (Read-Host -Prompt "Tenant Name")}
$permissions = Get-MgServicePrincipalPermissions
$permissions.Keys | ForEach-Object {$permissions["$_"] | Out-GridView -Title $_}

#>

function Write-HostWithTimeStamp {
    param(
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "The message to write")]
        [object]$Message
    )

    process {
        Write-Host -Object ("{0}`t{1}" -f [datetime]::Now.ToString("yyyyMMdd HH:mm:ss"), $message)
    }

}

function Get-MgServicePrincipalPermissions {

    param(
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Filter App Registration that begin witht his value.")]
        [string]$BeginsWith
    )

    process {

        $AppRoles = @()
        $AppRegistrations = @()
        if ([string]::IsNullOrEmpty($BeginsWith)) {
            $AppRegistrations += Get-MgApplication -Property "displayname,appId,id,keyCredentials,passwordCredentials"
        } else {
            $AppRegistrations += Get-MgApplication -Property "displayname,appId,id,keyCredentials,passwordCredentials" -Filter ("startswith(displayname, '{0}')" -f $BeginsWith)
        }

        Write-HostWithTimeStamp -Message ("Found {0} App Registrations" -f $AppRegistrations.Count)

        if ($AppRegistrations) {

            $ServicePrincipals = $AppRegistrations | ForEach-Object {Get-MgServicePrincipalByAppId -AppId $_.AppId -Verbose}
            Write-HostWithTimeStamp -Message ("Retrieved {0} Service Principals" -f $ServicePrincipals.Count)

            $AppRoleAssignments = $ServicePrincipals | ForEach-Object {Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id -Verbose} | Select-Object AppRoleId, CreatedDateTime, PrincipalId, ResourceId, ResourceDisplayName
            Write-HostWithTimeStamp -Message ("Retrieved {0} App Role Assignments" -f $AppRoleAssignments.Count)

            $AppRoles += @($AppRoleAssignments | Select-Object PrincipalId, ResourceDisplayName, ResourceId, AppRoleId) `
                        | ForEach-Object {$AppRoleAssignment = $_; Get-MgServicePrincipal -ServicePrincipalId $AppRoleAssignment.ResourceId}  `
                        | Select-Object -ExpandProperty AppRoles | Where-Object {$_.Id -eq $AppRoleAssignment.AppRoleId} `
                        | Select-Object @{n="ServicePrincipalId";e={$AppRoleAssignment.PrincipalId}}, @{n="ResourceName";e={$AppRoleAssignment.ResourceDisplayName}}, @{n="Type";e={"Application"}}, @{n="Permission";e={$_.Value}}
            Write-HostWithTimeStamp -Message ("Parsed App Role Assignments")

            $Oauth2PermissionGrants = $ServicePrincipals | ForEach-Object {Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $_.Id} | Select-Object ClientId, ConsentType, ResourceId, Scope
            Write-HostWithTimeStamp -Message ("Retrieved {0} Oauth2 Permission Grants" -f $Oauth2PermissionGrants.Count)

            $AppRoles += @($Oauth2PermissionGrants | Select-Object -Unique ClientId, ResourceId, Scope) `
                        | ForEach-Object {$Oauth2PermissionGrant = $_; Get-MgServicePrincipal -ServicePrincipalId $Oauth2PermissionGrant.ResourceId} `
                        | Select-Object @{n="ServicePrincipalId";e={$Oauth2PermissionGrant.ClientId}}, @{n="ResourceName";e={$_.DisplayName}}, @{n="Type";e={"Delegated"}}, @{n="Permission";e={$Oauth2PermissionGrant.Scope.Trim()}}
            Write-HostWithTimeStamp -Message ("Parsed Oauth2 Permission Grants")

            $AppRegistrations | Add-Member -Name ServicePrincipalId -MemberType ScriptProperty -Value {$AppRegistration = $this; ($ServicePrincipals | Where-Object {$_.AppId -eq $AppRegistration.AppId}).Id}

            $AppRoles | Add-Member -Name ServicePrincipal -MemberType ScriptProperty -Value {$AppRole = $this; ($ServicePrincipals | Where-Object {$_.Id -eq $AppRole.ServicePrincipalId}).DisplayName}

        }

        $Return = @{}

        $Return.Add("AppRegistrations"
            , (
                $AppRegistrations | Sort-Object DisplayName | Select-Object ServicePrincipalId, AppId, DisplayName `
                    , @{n="KeyCredentialExpires";e={$_.keyCredentials.EndDateTime -join "; "}} `
                    , @{n="PasswordCredentialExpires";e={$_.passwordCredentials.EndDateTime -join "; "}}
            )
        )

        $Return.Add("AppRoles"
            , (
                $AppRoles | Sort-Object ServicePrincipal, ResourceName | Select-Object ServicePrincipalId, ServicePrincipal, ResourceName, Type, Permission
            )
        )
             
        return $Return;
    }

}
