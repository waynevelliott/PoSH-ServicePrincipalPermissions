# PowerShell Script for Analyzing Service Principal Permissions in Azure AD

This script is designed to retrieve and analyze permissions associated with Service Principals in Azure Active Directory, using the Microsoft Graph PowerShell SDK. Here's a breakdown of its functionality:

1. Utility Function:
   - `Write-HostWithTimeStamp`: Adds timestamps to console output for logging purposes.

2. Main Function: Get-MgServicePrincipalPermissions
   - Optional parameter: $BeginsWith to filter App Registrations by display name.

3. App Registration Retrieval:
   - Fetches App Registrations, optionally filtered by display name.
   - Retrieves key properties: displayname, appId, id, keyCredentials, passwordCredentials.

4. Service Principal Mapping:
   - Maps App Registrations to their corresponding Service Principals.

5. Permission Analysis:
   - Retrieves and processes two types of permissions:
     a. App Role Assignments:
        - Fetches assignments for each Service Principal.
        - Parses assignments to extract detailed permission information.
     b. OAuth2 Permission Grants:
        - Retrieves OAuth2 permission grants for each Service Principal.
        - Processes grants to extract delegated permission details.

6. Data Enrichment:
   - Adds ServicePrincipalId to App Registrations for cross-referencing.
   - Adds ServicePrincipal display name to permission entries for readability.

7. Output:
   - Displays two formatted tables:
     a. App Registrations: Shows ServicePrincipalId, AppId, DisplayName, and credential expiration dates.
     b. Permissions: Lists ServicePrincipalId, ServicePrincipal name, ResourceName, Permission Type (Application/Delegated), and specific Permission.

Key Features:
- Comprehensive analysis of both application and delegated permissions.
- Efficient use of Microsoft Graph API for data retrieval.
- Ability to filter App Registrations for targeted analysis.
- Clear presentation of credential expiration dates for security auditing.

Use Cases:
- Security audits of application permissions in Azure AD.
- Identifying over-privileged applications.
- Tracking OAuth2 permission grants across the tenant.
- Monitoring credential expiration for App Registrations.

This script is particularly useful for Azure AD administrators and security professionals who need to maintain oversight of application permissions and ensure compliance with least privilege principles. It provides a comprehensive view of how service principals are configured and what access they have within the Azure AD environment.

### Run
![1  MgServicePrincipalPermissions - Run](https://github.com/user-attachments/assets/b3ae997d-5d41-4b7a-94e7-aecdaf98a489)

### App Registrations
![2  MgServicePrincipalPermissions - AppRegistrations](https://github.com/user-attachments/assets/44bf1ba8-e78d-43c5-913a-62f74664545a)

### App Registration Permissions
![3  MgServicePrincipalPermissions - AppRules](https://github.com/user-attachments/assets/771c2652-7954-4d50-ad57-e17587544b12)
