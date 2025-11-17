#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users

# - https://github.com/Azure-Samples/B2B-to-AD-Sync

#region 1 - Synopsis
<#
.SYNOPSIS
	Sample script to create shadow accounts in AD for Entra Application Proxy KCD delegation for Entra ID B2B Guest accounts.
	Includes options to:
	- Create shadow accounts in an OU of Entra ID guest users. This can be scoped to guests in a specific Entra ID group.
	- (Optional) Disable and move shadow accounts who no longer exist in Entra ID to a different OU.
	- (Optional) Delete shadow accounts in the OU who no longer exist in Entra ID.
	- (Optional) Restore orphaned shadow accounts if the corresponding guest user is re-added to the Entra ID group.
	Shadow accounts will be created with the following properties:
		-AccountPassword = random strong password
		-ChangePasswordAtLogon = $false
		-PasswordNeverExpires = $true
		-SmartcardLogonRequired = $true
	NOTE: This does not support group nesting in the Entra ID Group.
.DESCRIPTION
	Version: 2.1.1
	This is currently a beta level script and intended to be used as a demonstration script.
.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.
	Copyright (c) Microsoft Corporation. All rights reserved.
#>

<#
Recommended action items for production deployments:
- Consider adding additional filters for performance improvements
- Add error handling
#>
#endregion

[CmdletBinding(SupportsShouldProcess)]
Param(
	#If set to true, Shadow Accounts of guest users in the Entra ID group will be created in AD.
	[bool]$CreateMissingShadowAccounts = $true,
	#If set to true, disabled Shadow Accounts can be restored to the ShadowAccountOU and be re-enabled if the guest account is added again to the Entra ID Group.
	[bool]$RestoreDisabledAccounts = $true,

	# If set to true, no users will be created, disabled, deleted, or move OU's - overriding the values otherwise set.
	# A report will show what would happen if the script ran. E.g. what users would be created, disabled, deleted, etc.
	# (This parameter is already included as part of SupportsShouldProcess.)
	#$WhatIf = $false,

	# Only one of the following should be true. If both are True then disable action takes precedence.
	#  - # If set to true, guest users who are removed from the Entra ID group will be disabled and moved to the DisabledShadowAccountOU.
	[bool]$DisableOrphanedShadowAccounts = $true,
	#  - # If set to true, guest users who are removed from the Entra ID group will be deleted from AD.
	[bool]$DeleteOrphanedShadowAccounts = $false,

	# Requires additional configuration - refer to documentation.
	# Entra ID group's ObjectID.
	[string]$B2BGroupID,
	# If members are checked for userType of guest.
	# If not true, requires $B2BGroupID to be specified.
	[bool]$B2BEnforceGuest = $true,
	# DistinguishedName of an OU for placing shadow accounts.
	[Parameter(Mandatory=$true)]
	[string]$ShadowAccountOU,
	# DistinguishedName of an OU for moving disabled shadow accounts.
	[string]$DisabledShadowAccountOU,
	# Your application's Client ID.
	[Parameter(Mandatory=$true)]
	[string]$AppID,
	# Tenant ID of Entra ID.
	[Parameter(Mandatory=$true)]
	[string]$TenantID,
	# Certificate thumbprint used by application for authentication.
	[Parameter(Mandatory=$true)]
	[string]$Cert,

	# Set to have Create / Disable / Restore / Remove operations generated to the pipeline for further reporting, etc.
	[switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region 2 - Set script variables
# Keyed by Object ID.
$TenantGuestUsersHash = @{}
# Keyed by Object ID.
$UsersInB2BGroupHash = @{}
# Keyed by UserPrincipalName.
$B2bShadowAccountsHash = @{}
# Keyed by UserPrincipalName.
$B2bDisabledShadowAccountsHash = @{}
# Keyed by UserPrincipalName.
$ReenabledShadowAccounts = @{}
#endregion

if($null -eq $DisabledShadowAccountOU -and ($RestoreDisabledAccounts -or $DisableOrphanedShadowAccounts)){
	throw '$DisabledShadowAccountOU is required if $RestoreDisabledAccounts or $DisableOrphanedShadowAccounts are enabled.'
}

if(!$B2BEnforceGuest -and !$B2BGroupID){
	throw 'Either $B2BGroupID must be specified, or $B2BEnforceGuest must be set to $true.'
}

#region 3 - Populate Initial Hash Tables
Connect-MgGraph -ClientID $appID -TenantId $tenantID -CertificateThumbprint $Cert -NoWelcome
# If you want to run under a user context, run Connect-MgGraph -Scopes 'User.Read.All','Group.Read.All'

# Populate hash table with all Guest users from tenant using object ID as key.
$b2bFilter = 'accountEnabled eq true'
if ($B2BEnforceGuest) {
	$b2bFilter = 'userType eq ''Guest'' and ' + $b2bFilter
}
Get-MgUser -Filter $b2bFilter -All `
	| ForEach-Object {
		$TenantGuestUsersHash[$_.Id] = $_
	}

# Populate hash table with membership of target group from Entra ID using object ID as key.
if($B2BGroupID){
	Get-MgGroupMember -GroupId $B2BGroupID -All `
		| ForEach-Object{
			$id = $_.Id
			if ($TenantGuestUsersHash.ContainsKey($id)) {
				$UsersInB2BGroupHash[$id] = $_
			} else {
				Write-Warning "Found user in B2B group but not an enabled B2B guest: $id"
			}
		}
}else{
	$TenantGuestUsersHash.Values `
	| ForEach-Object{
		$UsersInB2BGroupHash[$_.Id] = $_
	}
}

# Populate hash table with all accounts in shadow account OU using UPN as key.
# Search for disabled accounts first, to account for cases
#   where the $DisabledShadowAccountOU is nested under the $ShadowAccountOU .
if($DisabledShadowAccountOU){
	Get-ADUser -Filter * -SearchBase $DisabledShadowAccountOU `
		| Select-Object UserPrincipalName, Name, Description `
		| ForEach-Object {
			$B2bDisabledShadowAccountsHash[$_.UserPrincipalName] = $_
		}
}

Get-ADUser -Filter * -SearchBase $ShadowAccountOU `
	| Select-Object UserPrincipalName, Name, Description `
	| ForEach-Object {
		if (!$B2bDisabledShadowAccountsHash.ContainsKey($_.UserPrincipalName)) {
			$B2bShadowAccountsHash[$_.UserPrincipalName] = $_
		}
	}

#endregion

#region 4 - Populate Hash Table Differencing Lists
foreach ($key in $($UsersInB2BGroupHash.Keys)) {
	$tenantGuestUpn = $TenantGuestUsersHash[$key].UserPrincipalName
	# B2B guest user already has a shadow account.
	# Remove from both lists, we'll then end up with 2 differencing lists.
	if ($B2bShadowAccountsHash.ContainsKey($tenantGuestUpn)) {
		$UsersInB2BGroupHash.Remove($key)
		$B2bShadowAccountsHash.Remove($tenantGuestUpn)
	} elseif ($B2bDisabledShadowAccountsHash.ContainsKey($tenantGuestUpn)) {
		$UsersInB2BGroupHash.Remove($key)
		$ReenabledShadowAccounts.Add($tenantGuestUpn, $key)
	}
}
#endregion

#region 5 - Create Shadow Accounts
if ($CreateMissingShadowAccounts -eq $true) {
	$rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
	$passBytes = New-Object Byte[] 24
	$sortBytes = New-Object Byte[] 8
	foreach ($key in $($UsersInB2BGroupHash.keys)) {
		$samAccountName = $TenantGuestUsersHash[$key].UserPrincipalName.Replace('.', '-')
		$samAccountName = $samAccountName.Substring(0, [System.Math]::Min(20, $samAccountName.Length))

		$samBase = $samAccountName
		$samIdx = 0
		while (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'") {
			$suffix = $samIdx.ToString()
			$samAccountName = $samBase.Substring(0, `
				[System.Math]::Min(20 - $suffix.Length, $samAccountName.Length)) + $suffix
		}

		$displayName = $TenantGuestUsersHash[$key].UserPrincipalName.Split('#')[0]

		# Generate random password.
		$rand.GetBytes($passBytes)
		$secRandPassword = [System.Security.SecureString]::new()
		# Ensure password includes sufficient characters from different character categories to meet various password complexity requirements.
		# (Upper, Lower, Numbers, Special)
		(((65..90), (97..122), (48..57), ((33..47) + (58..64) + (91..96) + (123..126))) `
				| ForEach-Object{[char[]]($_ | Get-Random -Count 2)}) `
			+ [System.Convert]::ToBase64String($passBytes).ToCharArray() `
			| Sort-Object {$rand.GetBytes($sortBytes); [System.BitConverter]::ToInt64($sortBytes, 0)} `
			| ForEach-Object{$secRandPassword.AppendChar($_)}
		$secRandPassword.MakeReadOnly()

		$action = 'Create'
		$shadowUpn = $TenantGuestUsersHash[$key].UserPrincipalName
		if ($PSCmdlet.ShouldProcess($shadowUpn, $action)) {
			$user = New-ADUser -Name $displayName `
					-SamAccountName $samAccountName `
					-Path $ShadowAccountOU `
					-UserPrincipalName $shadowUpn `
					-Description 'Shadow account of Entra ID guest account.' `
					-DisplayName $TenantGuestUsersHash[$key].DisplayName `
					-AccountPassword $secRandPassword `
					-ChangePasswordAtLogon $false `
					-PasswordNeverExpires $true `
					-SmartcardLogonRequired $true `
					-PassThru `
				| Enable-ADAccount -PassThru
			if ($PassThru) {
				[PSCustomObject]@{
					'Action' = $action
					'User' = $user
				}
			}
		}
	}
	$rand.Dispose()
}
#endregion

#region 6 - Clean up
# Restoring disabled users that have been added back to the Entra ID group.
if ($RestoreDisabledAccounts -eq $true) {
	foreach ($shadow in $($ReenabledShadowAccounts.keys)) {
		$action = 'Restore'
		if ($PSCmdlet.ShouldProcess($shadow, $action)) {
			$user = Get-ADUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $DisabledShadowAccountOU `
				| Set-ADUser -Enabled $true -Description 'Shadow account of Entra ID guest account.' -PassThru `
				| Move-ADObject -TargetPath $ShadowAccountOU -PassThru
			if ($PassThru) {
				[PSCustomObject]@{
					'Action' = $action
					'User' = $user
				}
			}
		}
	}
}

# Clean up Shadow accounts that have been removed from the Entra ID group.
if ($DisableOrphanedShadowAccounts -eq $true -or $DeleteOrphanedShadowAccounts -eq $true) {
	foreach ($shadow in $($B2bShadowAccountsHash.keys)) {
		# $upn = the key from B2bShadowAccountsHash = $shadow
		# disable operation takes precedence over deletion
		if ($DisableOrphanedShadowAccounts -eq $true) {
			$action = 'Disable'
			if ($PSCmdlet.ShouldProcess($shadow, $action)) {
				$user = Get-ADUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU `
					| Set-ADUser -Enabled $false -Description 'Disabled pending removal.' -PassThru `
					| Move-ADObject -TargetPath $DisabledShadowAccountOU -PassThru
				if ($PassThru) {
					[PSCustomObject]@{
						'Action' = $action
						'User' = $user
					}
				}
			}
		} elseif ($DeleteOrphanedShadowAccounts -eq $true) {
			$action = 'Remove'
			if ($PSCmdlet.ShouldProcess($shadow, $action)) {
				$user = Get-ADUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU
				$user | Remove-ADUser -Confirm:$false
				if ($PassThru) {
					[PSCustomObject]@{
						'Action' = $action
						'User' = $user
					}
				}
			}
		}
	}
}
#endregion
