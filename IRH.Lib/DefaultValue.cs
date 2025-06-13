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
        public const string TenantID = "common";
        public const string AppID = "c0849608-c8b9-4e86-b37d-fce972a0a7f6";
        public static readonly AuthType AuthType = AuthType.DeviceCode;
        public static readonly List<string> AzureMfaPermissions = new List<string>() { "Directory.Read.All", "UserAuthenticationMethod.Read.All" };
        public static readonly Uri DeviceLoginUrl = new Uri("https://microsoft.com/devicelogin");
        public static readonly ReportType ReportType = ReportType.CLI;
        public static readonly ReportPrintLevel PrintLevel = ReportPrintLevel.Brief;
    }
}
