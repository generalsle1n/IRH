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

        public bool Install()
        {
            //Impersonation a = new Impersonation()
            File.Copy(SourceBinary, @$"\\{DestinationPC}\c$\temp\lol");
            return false;
        }
    }
}
