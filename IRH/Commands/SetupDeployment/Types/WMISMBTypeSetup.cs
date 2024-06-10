using Microsoft.Management.Infrastructure;
using Microsoft.Win32.SafeHandles;
using Serilog.Core;
using SimpleImpersonation;
using System.Security.Principal;

namespace IRH.Commands.SetupDeployment.Types
{
    public class WMISMBTypeSetup : ISetupType
    {
        public string SourceBinary { get; set; }
        public string Parameters { get; set; }
        public string DestinationPC { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public Logger Logger { get; set; }

        private const string _wmiNamespace = @"root\cimv2";
        private const string _wmiProcessClass = "Win32_Process";
        private const string _wmiProcessMethodName = "Create";
        private const string _createParameterName = "CommandLine";
        private const string _wmiProcessIDPropertyName = "ProcessId";
        private const string _wmiDialect = "WQL";
        private const int _sleepTimeForWait = 2500;
        {
            //Impersonation a = new Impersonation()
            File.Copy(SourceBinary, @$"\\{DestinationPC}\c$\temp\lol");
            return false;
        }
    }
}
