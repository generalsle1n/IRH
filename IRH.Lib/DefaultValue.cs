using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Deployment.Esxi;
using IRH.Lib.Model.General;
using IRH.Lib.Model.Remote.CopyFile;
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
        public const int DefaultEsxiPort = 443;
        public const string EsxiPropertyNameValue = "name";
        public const string EsxiPropertyConfigUuidValue = "config.uuid";
        public const string EsxiPropertyConfigGuestFullName = "config.guestFullName";
        public const string EsxiPropertyConfigGuestIdValue = "config.guestId";
        public const string EsxiPropertyTaskValue = "Task";
        public const string EsxiPropertyTaskInfoStateValue = "info.state";
        public const string EsxiPropertyTaskInfoErrorValue = "info.error";
        public const string EsxiPropertyTaskInfoProgressValue = "info.progress";
        public const string EsxiPropertyTaskInfoDescriptionValue = "info.descriptionId";
        public const string EsxiPropertyRuntimePowerStateValue = "runtime.powerState";
        public const string EsxiPropertyGuestToolsRunningStatusValue = "guest.toolsRunningStatus";
        public const string EsxiPropertyGuestGuestFullNameValue = "guest.guestFullName";
        public const string EsxiPropertyGuestToolsRunningRunStatus = "guestToolsRunning";
        public const string EsxiPropertyFileManagerNameValue = "fileManager";
        public const string EsxiPropertyProcessManagerNameValue = "processManager";
        public const string EsxiPropertyAuthManagerNameValue = "authManager";
        public const string EsxiPropertyTypeHostSpec = "HostSystem";
        public const string EsxiPropertyNetworkPath = "network";
        public const string EsxiPropertyVirtualMachineTypeValue = "VirtualMachine";
        public const string EsxiPropertyNetworkHostPathValue = "runtime.host";
        public const string EsxiPropertyNetworkTraversalValue = "hostTraversal";
        public const string EsxiPropertyVMHardwareDeviceValue = "config.hardware.device";
        public const string DefaultWindowsTempPath = @"C:\Windows\Temp";
        public const string DefaultWindowsMsiExecPath = @"C:\Windows\System32\msiexec.exe";
        public const string DefaultWindowsCmdPath = @"C:\Windows\System32\cmd.exe";
        public const string DefaultWindowsMsiExecPrefixArguments = "/I";
        public const string DefaultWindowsMsiExecSuffixArguments = "/qn";
        public const string DefaultWindowsCmdPrefixArguments = "/C";
        public const string DefaultWindowsExeSuffixArguments = "";
        public static readonly AuthType AuthType = AuthType.DeviceCode;
        public static readonly CopyType CopyType = CopyType.Smb;
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
        public static readonly DeploymentType EsxiDeploymentType = DeploymentType.MSIExec;
        public static readonly WebScheme EsxiDefaultScheme = WebScheme.Http;
    }
}
