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

        public void Install()
        {
            UserCredentials Credentials = new UserCredentials($"{DestinationPC}\\{Username}", $"{Password}");
            Logger.Information($"Try to Login to {Username}@{DestinationPC}");

            SafeAccessTokenHandle UserHandle = Credentials.LogonUser(LogonType.NewCredentials, LogonProvider.WINNT50);

            string PartPath = $@"\Windows\Temp\{Guid.NewGuid().ToString()}";
            string TempPath = $@"\\{DestinationPC}\c${PartPath}";
            string WindowsPath = $@"C:{PartPath}";
            string FileName = Path.GetFileName(SourceBinary);
            string AbsoultePathNetwork = Path.Combine(TempPath, FileName);
            string AbsoultePathLocal = Path.Combine(WindowsPath, FileName);

            WindowsIdentity.RunImpersonated(UserHandle, () =>
            {
                try
                {
                    Directory.CreateDirectory(TempPath);
                    Logger.Information($"Created Path {TempPath}");

                    Logger.Information($"Start Copy to {AbsoultePathNetwork}");
                    File.Copy(SourceBinary, AbsoultePathNetwork);
                    Logger.Information($"File coppied");
                }
                catch (IOException Exception)
                {
                    Logger.Fatal(Exception.Message);
                    Directory.Delete(AbsoultePathNetwork, true);
                }
            });

            CimMethodResult StartProcess = null;
            CimMethodParametersCollection Parameter = new CimMethodParametersCollection();
            Parameter.Add(CimMethodParameter.Create(_createParameterName, $"{AbsoultePathLocal} {Parameters}", CimFlags.Property));

            WindowsIdentity.RunImpersonated(UserHandle, () =>
            {
                Logger.Information($"Try to Connect via WMI to {DestinationPC}");
                CimSession Session = CimSession.Create($"{DestinationPC}");
                try
                {
                    StartProcess = Session.InvokeMethod(_wmiNamespace, _wmiProcessClass, _wmiProcessMethodName, Parameter);
                }
                catch (CimException Exception)
                {
                    Logger.Fatal(Exception.Message);
                }
            });

            UInt32 ProcessID = (UInt32)StartProcess.OutParameters.Where(i => i.Name.Equals(_wmiProcessIDPropertyName)).First().Value;
            Logger.Information($"Process returned from WMI {ProcessID}");

            WaitForProcess(ProcessID);

            Directory.Delete(TempPath, true);
            Logger.Information($"Cleaned up Path {TempPath}");
        }

        private bool WaitForProcess(UInt32 PID)
        {
            UserCredentials Credentials = new UserCredentials($"{DestinationPC}\\{Username}", $"{Password}");
            Logger.Information($"Try to Login to {Username}@{DestinationPC}");

            SafeAccessTokenHandle UserHandle = Credentials.LogonUser(LogonType.NewCredentials, LogonProvider.WINNT50);
            
            string WQLQuery = $"SELECT * FROM {_wmiProcessClass} where {_wmiProcessIDPropertyName}={PID}";
            Logger.Information($"WQL Query generated: {WQLQuery}");

            WindowsIdentity.RunImpersonated(UserHandle, () =>
            {
                CimSession mySession = CimSession.Create($"{DestinationPC}");
                bool Print = false;
                while (true)
                {
                    IEnumerable<CimInstance> queryInstance = mySession.QueryInstances(_wmiNamespace,_wmiDialect, WQLQuery);
                    if (queryInstance.Count() == 0)
                    {
                        Logger.Information($"Process Finished ({PID})");
                        break;
                        
                    }
                    else
                    {
                        if (Print)
                        {
                            Logger.Information("Wait for Process to be finished");
                            Print = false;
                        }
                        else
                        {
                            Print = true;
                        }
                        
                        Thread.Sleep(_sleepTimeForWait);
                    }
                }
            });

            return true;
        }
    }
}
