using IRH.Remote.Commands.General.Model;
using Microsoft.Management.Infrastructure;
using Serilog.Configuration;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.General
{
    internal class ProcessHelper
    {
        private readonly Logger _logger;
        private const string _wmiNamespace = @"root\cimv2";
        private const string _wmiClass = "Win32_Process";
        private const string _settingWmiClass = "Win32_ProcessStartup";
        private const string _wmiMethodCreation = "Create";
        private const string _currentDirectory = @"C:\Windows\System32";
        private const string _binaryName = "powershell.exe";
        private const string _resultPropertyName = "ProcessId";
        private const string _wmiQueryDialect = "WQL";
        private const int _wmiQueryTimeout = 1000;

        internal static bool CreatePowershellProcess(CimSession Session, string PowershellScript, Logger logger, ShowWindow WindowMode = ShowWindow.SW_HIDE, bool Wait = true)
        {
            bool Result = false;
            CimMethodParametersCollection Parameters = new CimMethodParametersCollection();

            CimInstance StartupInfo = new CimInstance(_settingWmiClass);
            
            StartupInfo.CimInstanceProperties.Add(CimProperty.Create("ShowWindow", ShowWindow.SW_HIDE, CimType.UInt16, CimFlags.None)); // SW_SHOWNORMAL

            Parameters.Add(CimMethodParameter.Create("CommandLine", $"{_binaryName} -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand {PowershellScript}", CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("CurrentDirectory", _currentDirectory, CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("ProcessStartupInformation", StartupInfo, CimFlags.Parameter));

            CimMethodResult CimResult = Session.InvokeMethod(_wmiNamespace, _wmiClass, _wmiMethodCreation, Parameters);

            if ((uint)CimResult.ReturnValue.Value == (uint)0)
            {
                uint PID = (uint)CimResult.OutParameters[_resultPropertyName].Value;
                Result = true;
                logger.Information($"Powershell Script started successfully (PID: {PID})");

                while(Wait == true)
                {
                    IEnumerable<CimInstance> ProcessList = Session.QueryInstances(_wmiNamespace, _wmiQueryDialect, $"SELECT {_resultPropertyName} FROM Win32_Process WHERE {_resultPropertyName} = {PID}");
                    if (!ProcessList.Any())
                    {
                        break;
                    }
                    else
                    {
                        Thread.Sleep(_wmiQueryTimeout);
                    }
                }
            }
            else
            {
                logger.Error("Unable to start powershell script");
            }

            return Result;
        }
    }
}