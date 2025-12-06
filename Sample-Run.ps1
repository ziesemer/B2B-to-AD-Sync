.\B2B-AAD-to-AD-Sync.ps1 `
	-B2BGroupID '********-****-****-****-************' `
	-ShadowAccountOU 'OU=EID-B2B-Shadow,OU=Example,DC=example,DC=com' `
	-DisabledShadowAccountOU 'OU=Disabled,OU=AAD-B2B-Shadow,OU=EID-B2B-Shadow,OU=Example,DC=example,DC=com' `
	-AppID '********-****-****-****-************' `
	-TenantID '********-****-****-****-************' `
	-Cert '****************************************' `
	-PassThru `
| Select-Object -Property Action, @{n='UserPrincipalName'; e={$_.User.UserPrincipalName}}, @{n='SamAccountName'; e={$_.User.SamAccountName}} `
| Format-List
