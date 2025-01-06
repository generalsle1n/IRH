using IRH.Remote.Commands.General.Model;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.General
{
    internal class ProductHelper
    {
        private const string _wmiNamespace = @"root\cimv2";
        private const string _wmiClass = "Win32_Product";
        private const string _wmiMethodCreation = "Install";
        private const string _timeOutexecption = "HRESULT 0x40004";

        internal static bool InstallSingleMSI(CimSession Session, string PathMsi, string Option, int Timeout, Logger logger)
        {
            bool Result = false;
            CimMethodParametersCollection Parameters = new CimMethodParametersCollection();

            Parameters.Add(CimMethodParameter.Create("PackageLocation", PathMsi, CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("Options", Option, CimType.String, CimFlags.In));
            Parameters.Add(CimMethodParameter.Create("AllUsers", true, CimType.Boolean, CimFlags.In));

            CimOperationOptions Options = new CimOperationOptions()
            {
                Timeout = TimeSpan.FromSeconds(Timeout)
            };

            try
            {
                logger.Information("Starting installation of software");

                CimMethodResult CimResult = Session.InvokeMethod(_wmiNamespace, _wmiClass, _wmiMethodCreation, Parameters, Options);
                
                if ((uint)CimResult.ReturnValue.Value == (uint)0)
                {
                    logger.Information("Software installed successfully");
                    Result = true;
                }
                else
                {
                    logger.Error("Software unable to install");
                }
            }
            catch(CimException e)
            {
                if(e.MessageId.Equals(_timeOutexecption))
                {
                    logger.Warning("WMI aborted during timeout, probaly extend the timeout");
                }
            }

            return Result;
        }
    }
}
