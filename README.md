# IRH

I've created a suite of some little helper tools within incident response when dealing with security breaches. These tools provide essential features for IT security professionals, making it easier to manage and respond to incidents effectively.



[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)

 


## Tech Stack

**Framework:** ![.Net](https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white) 
![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=c-sharp&logoColor=white)


**OS:** ![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Mac](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)





## Demo

![App Screenshot](https://raw.githubusercontent.com/generalsle1n/IRH/master/blob/AzureMFADemo.gif)


## Run Locally to Develop

Clone the project

```bash
  git clone https://github.com/generalsle1n/IRH
```

Go to the project directory

```bash
  cd IRH\IRH
```

Install dependencies

```bash
  dotnet restore
```

Build and Start the Cli Tool

```bash
  dotnet run
```


## Installation for Production Usage

Publish the project with the following settings
- Config:               ```Release```
- TargetFramework:      ```.Net 8```
- Deployment:           ```SelfContained```
- Singlefile:           ```true```
- ReadyToRun:           ```false```
- Remove not used Code: ```false```
    
## Roadmap

- Add EDiscovery Search and Delete Specifc Mails from all Mailboxes in the exchange environment
- Add Elasticsearch as Output Format
- Add Auditlog Search from purview via Graph API
- Parralel Working, so you dont need to wait on an single blocking task

## Lessons Learned

Many 😀, finishing this list, when the project is "done"

## Feedback

If you have any feedback, please open an issue or an pull request 😀


## Features
### LDAP Directory Monitoring (Via LDAP Events and not from Security Logs)
The LDAPMonitor tool allows for continuous monitoring of LDAP directories. It can:

- Establish a connection to a specified LDAP server using provided credentials.
- Monitor specified LDAP paths for changes.
- Log any changes detected in the LDAP directory, including detailed information about the modified objects and attributes.


### Azure MFA Reporting
The AzureMFA tool enables comprehensive reporting on Azure Multi-Factor Authentication (MFA) settings. It can:

- Connect to Azure Active Directory using Device Code Authentication.
- Retrieve user data, including MFA configurations.
- Filter users by group membership, that should be processed.
- Provide detailed reports on MFA methods used by each user, available in both CLI and JSON formats.
- Print detailed information on each MFA method configured for users.

## Azure Audit Logs

### Login Specific Reporting
The LoginAudit tool is designed to provide in-depth reporting on login-related activities recorded in the Azure Audit Log.

- Customizable Investigation Period
- Custom Permission Scopes
- Activity Filters: Focus on specific login activities, such as "WrongUsername", "UserLoggedIn", and "UserLoginFailed".
- Multiple Output Formats
- Advanced Filtering Options

### Exchange Specific Reporting
The LoginAudit tool is designed to provide in-depth reporting on login-related activities recorded in the Azure Audit Log.

- Customizable Investigation Period
- Custom Permission Scopes
- Activity Filters: Focus on specific login activities, such as "New-TransportRule", "New-InboxRule", "Set-Mailbox", "Set-TransportRule", and "Set-InboxRule.
- Multiple Output Formats
- Advanced Filtering Options

## FAQ

#### Can i add by myself some new features?

Yeah sure --> If you think its good, create an pull request

#### Does it can run offline?

Some features yes, but the Graph Api requires an internet connection



## Parameters
To run this project, you need to specify the paramters in the command line tool of youre choice

### Azure MFA Reporting
#### Command: ``` -Azure -AMFA ```
###### Description: Fetches and reports the Multi-Factor Authentication (MFA) settings for Azure AD users, crucial for verifying the security posture and compliance of user accounts.

##### Options: 
```bash
-G, --Group (optional): Filter users by group ID(s) to focus on specific subsets of users.
-P, --PermissionScope (optional): Define custom permission scopes for Azure API access (default: Directory.Read.All, UserAuthenticationMethod.Read.All).
-A, --AppID (required): Application ID for Azure AD.
-T, --Tenant (optional): Tenant ID (default: common).
-R, --Report (optional): Report format (default: CLI; options: CLI, Json, CLIAndJson).
-PL, --PrintLevel (optional): Detail level in the report (default: Brief; options: Brief, Info, Detailed, Hacky).
```

##### Example:
```bash
IRH.exe -Azure -AMFA --AppID "your-app-id" --Tenant "your-tenant-id" --Report CLI -PL Info

./IRH -Azure -AMFA --AppID "your-app-id" --Tenant "your-tenant-id" --Report CLI -PL Info

dotnet run -Azure -AMFA --AppID "your-app-id" --Tenant "your-tenant-id" --Report CLI -PL Info
```

### Azure Audit Login Reporting
#### Command: ``` -Azure -Audit -Login ```
###### Description: Fetches and reports the the most important Login related Infos for Azure AD users, crucial for verifying the security posture and compliance of user accounts.

##### Options: 
```bash
-P, --PermissionScope (optional): Define custom permission scopes for Azure API access (default: Directory.Read.All, UserAuthenticationMethod.Read.All).
-A, --AppID (required): Application ID for Azure AD.
-T, --Tenant (optional): Tenant ID (default: common).
-R, --Report (optional): Report format (default: CLI; options: CLI, Json, CLIAndJson).
-PL, --PrintLevel (optional): Detail level in the report (default: Brief; options: Brief, Info, Detailed, Hacky).
-S, --Start (optional): Enter the Start of the Investigation (Just in Format DD.MM.YYYY))
-E, --End (optional): Enter the End of the Investigation (Just in Format DD.MM.YYYY))
-AC, --Activities (optional): Enter the Default Activities that should be searched in the Audit Logs (Seperated By Whitespace (default:MailboxLogin|UserLoggedIn|UserLoginFailed)
-QT, --QueryWait (optional): Enter the Value how long to wait between the single query checks (In Seconds) (default: 10)
-EQ, --ExisitingQuery (optional): Enter the Name of the Existing Query to use the result
 -FP, --FilterParameter (optional): Filter on Parameternames (Displayfilter), Wildcards are supported (This Setting works only on Printlevel Info and above) its also possible to enter multiple values seperated by whitespace
-FV, --FilterValue (optional): Filter on Paramtervalue (Datafilter): Syntax --> ParamterName:FilterValue (Example: Id:241af6fe-955d-4884-b27d-08dc93695d85), if you specify multiple serpated by whitespace it have an AND Operator
-AU, --AuthType (optional): Enter the the process how you want to authenticate (default:DeviceCode)
```

### Azure Audit Exchange Reporting
#### Command: ``` -Azure -Audit -Exchange ```
###### Description: Fetches and reports the the most important Exchange related Infos for Office365 Mailboxen, crucial for verifying the security posture and compliance of user accounts.

##### Options: 
```bash
-P, --PermissionScope (optional): Define custom permission scopes for Azure API access (default: Directory.Read.All, UserAuthenticationMethod.Read.All).
-A, --AppID (required): Application ID for Azure AD.
-T, --Tenant (optional): Tenant ID (default: common).
-R, --Report (optional): Report format (default: CLI; options: CLI, Json, CLIAndJson).
-PL, --PrintLevel (optional): Detail level in the report (default: Brief; options: Brief, Info, Detailed, Hacky).
-S, --Start (optional): Enter the Start of the Investigation (Just in Format DD.MM.YYYY))
-E, --End (optional): Enter the End of the Investigation (Just in Format DD.MM.YYYY))
-AC, --Activities (optional): Enter the Default Activities that should be searched in the Audit Logs (Seperated By Whitespace (default:MailboxLogin|UserLoggedIn|UserLoginFailed)
-QT, --QueryWait (optional): Enter the Value how long to wait between the single query checks (In Seconds) (default: 10)
-EQ, --ExisitingQuery (optional): Enter the Name of the Existing Query to use the result
 -FP, --FilterParameter (optional): Filter on Parameternames (Displayfilter), Wildcards are supported (This Setting works only on Printlevel Info and above) its also possible to enter multiple values seperated by whitespace
-FV, --FilterValue (optional): Filter on Paramtervalue (Datafilter): Syntax --> ParamterName:FilterValue (Example: Id:241af6fe-955d-4884-b27d-08dc93695d85), if you specify multiple serpated by whitespace it have an AND Operator
-AU, --AuthType (optional): Enter the the process how you want to authenticate (default:DeviceCode)
```


##### Example:
```bash
IRH.exe -Azure -Audit -Exchange --AppID "your-app-id" --Tenant "your-tenant-id" --Report CLI -PL Info

./IRH -Azure -Audit -Exchange --AppID "your-app-id" --Tenant "your-tenant-id" --Report CLI -PL Info

dotnet run -Azure -Audit -Exchange --AppID "your-app-id" --Tenant "your-tenant-id" --Report CLI -PL Info
```

### Ldap Monitoring
#### Command: ``` -LS ```
###### Description: Monitors an LDAP path for changes, allowing security teams to detect unauthorized or suspicious modifications.

##### Options: 
```bash
-N, --Name (required): The domain name of the LDAP server.
-U, --User (required): Username for LDAP connection.
-P, --Password (required): Password for LDAP connection.
-p, --Port (optional): Port for LDAP connection (default: 389).
```

##### Example:
```bash
IRH.exe -LS --Name "example.com" --User "admin" --Password "password"

./IRH -LS --Name "example.com" --User "admin" --Password "password"

dotnet run -LS --Name "example.com" --User "admin" --Password "password"
```

## Authors

- [@Niels Schuler](https://github.com/generalsle1n/)


## Acknowledgements

 - [GraphApi: Microsoft](https://github.com/microsoftgraph/msgraph-sdk-dotnet)
 - [Win32 Impersonation: SimpleImpersonation](https://github.com/mattjohnsonpint/SimpleImpersonation)
 - [Logging Framework: Serilog](https://github.com/serilog/serilog)
 - [Logging Framework: Serilog Console Extension](https://github.com/serilog/serilog-sinks-console)
