using IRH.Remote.Commands.General.Model;
using Microsoft.Management.Infrastructure;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.General
{
    internal class RegistryHelper
    {
        private readonly Logger _logger;
        private const string _wmiNamespace = @"root\cimv2";
        private const string _wmiClass = "StdRegProv";
        private const string _wmiMethodCreation = "SetBinaryValue";
        private const string _wmiMethodDeletion = "DeleteValue";

        internal static bool CreateRegistryValue(CimSession Session, string RegistryKey, string RegistryValueName, byte[] RegistryValue, Logger logger, RegistryTree Tree = RegistryTree.HKEY_CURRENT_USER)
        {
            bool Result = false;
            CimMethodParametersCollection Parameters = new CimMethodParametersCollection();

            Parameters.Add(CimMethodParameter.Create("hDefKey", Tree, CimType.UInt32, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("sSubKeyName", RegistryKey, CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("sValueName", RegistryValueName, CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("uValue", RegistryValue, CimType.UInt8Array, CimFlags.In));

            CimMethodResult CimResult = Session.InvokeMethod(_wmiNamespace, _wmiClass, _wmiMethodCreation, Parameters);
            
            if((uint)CimResult.ReturnValue.Value == (uint)0)
            {
                Result = true;
                logger.Information("Registry Value created successfully");
            }
            else
            {
                logger.Error("Unable to create Registry Value");
            }

            return Result;
        }
        
        internal static bool DeleteRegistryValue(CimSession Session, string RegistryKey, string RegistryValueName, Logger logger, RegistryTree Tree = RegistryTree.HKEY_CURRENT_USER)
        {
            bool Result = false;
            CimMethodParametersCollection Parameters = new CimMethodParametersCollection();

            Parameters.Add(CimMethodParameter.Create("hDefKey", Tree, CimType.UInt32, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("sSubKeyName", RegistryKey, CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("sValueName", RegistryValueName, CimType.String, CimFlags.In));

            CimMethodResult CimResult = Session.InvokeMethod(_wmiNamespace, _wmiClass, _wmiMethodDeletion, Parameters);

            if ((uint)CimResult.ReturnValue.Value == (uint)0)
            {
                Result = true;
                logger.Information("Registry Value deleted successfully");
            }
            else
            {
                logger.Error("Unable to delete Registry Value");
            }

            return Result;
        }
    }
}
