# Theory
*   What is Azure
    *   Cloud-based IAM provider for o365 AD environments
    *   Create an Azure Directory
        *   From scratch:
            *   Register a public domain for your organization
            *   Sign-in to the [Azure Portal](https://portal.azure.com) → Sign-up for a [subcription](https://portal.azure.com/#blade/Microsoft_Azure_Billing/SubscriptionsBlade) plan with “Owner”
            *   “Add custom domain” → Complete the procedure → save the TXT record info and put it in the original DNS records
            *   Create a tenant and associate the subscription to it, you now have an Azure instance
        *   From a local AD
            *   Install [Azure AD Connect](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sync-whatis) on a server in the forest root
            *   Two accounts get created, to indicate that Azure is being deployed.
                *   `MSOL_[UUID]` in the Active Directory.
                *   `Sync_[HOSTNAME_OF_SERVER]_[UUID]` in Azure AD. 
                *   You still maintain local identities, as well as new cloud ones, passwords get synced on the cloud via “PSH”
    *   Resources
        *   Tenants
            *   Corresponds to an AD instance, can have a subscription to deploy resources
            *   An AD instance can have P1 / P2 licenses to access more features in ID management
            *   Contains users, groups, devices, service principals, resources
            *   Users can interact with resources based on:
                *   [Intune](https://endpoint.microsoft.com/)\-managed conditional access
                *   Device-level configuration and baselines
                *   MFA/SSO/OAuth Sign-In to local o365 applications
                *   Group roles in the `Resource Manager` 
            *   `*.graph.windows.net`
            *   `*.onmicrosoft.com`
        *   Azure App Service / VMs
            *   `*.cloudapp.azure.com`
            *   `*.cloudapp.net`
            *   `*.azurewebsites.net`
            *   `*.azure-mobile.net`
        *   Storages
            *   `*.blob.core.windows.net`
            *   `*.file.core.windows.net`
            *   `*.queue.core.windows.net`
            *   `*.table.core.windows.net`
        *   Databases
            *   `*.database.windows.net`
            *   `*.cosmos.azure.com`
            *   `*.documents.azure.com`
            *   `*.vault.azure.net`