using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib
{
    public class DefaultValue
    {
        public const string TenantId = "common";
        public const string AppId = "c0849608-c8b9-4e86-b37d-fce972a0a7f6";
        public const string OperatorDisplayName = "IRH_Scanner_Operator_For_User_Access";
        public const string DefaultDateFormat = "yyyy-MM-dd";
        public const int DefaultSecretPeriod = 30;
        public const int DefaultWaitTime = 1000;
        public static readonly AuthType AuthType = AuthType.DeviceCode;
        public static readonly List<string> AzureMfaPermissions = new List<string>() { "Directory.Read.All", "UserAuthenticationMethod.Read.All" };
        public static readonly List<string> AzureSessionRevokePermissions = new List<string>() { "Directory.Read.All", "User.RevokeSessions.All"};
        public static readonly List<string> AzureLoginAuditPermissions = new List<string>() { "Directory.Read.All", "AuditLogsQuery.Read.All"};
        public static readonly List<string> AzureMailCleanupPermissions = new List<string>() { "Directory.Read.All", "Mail.ReadWrite", "MailboxSettings.ReadWrite" };
        public static readonly List<string> AzureAppRegistrationPermissions = new List<string>() {"Directory.Read.All", "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"};
        public static readonly List<string> AzureDefaultPermission = new List<string>(){ "https://graph.microsoft.com/.default" };
        public static readonly List<string> AzureLoginAuditActivities = new List<string>() { "MailboxLogin", "UserLoggedIn", "UserLoginFailed"};
        public static readonly Uri DeviceLoginUrl = new Uri("https://microsoft.com/devicelogin");
        public static readonly ReportType ReportType = ReportType.CLI;
        public static readonly ReportPrintLevel PrintLevel = ReportPrintLevel.Brief;
    }
}
