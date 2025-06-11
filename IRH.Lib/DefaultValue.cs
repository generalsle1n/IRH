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
        public readonly static AuthType AuthType = AuthType.DeviceCode;
        public readonly static List<string> AzureMfaPermissions = new List<string>() { "Directory.Read.All", "UserAuthenticationMethod.Read.All" };
        public readonly static ReportType ReportType = ReportType.CLI;
    }
}
