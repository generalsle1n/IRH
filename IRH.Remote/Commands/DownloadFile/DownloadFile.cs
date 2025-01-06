using IRH.Remote.Commands.General.Model;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.DownloadFile
{
    internal class DownloadFile
    {
        private const string _commandName = "--Download";
        private const string _commandDescription = "Download an File on from the remote Machine";
        private const string _commandAlias = "-D";

        private const string _deploymentTypeName = "--Type";
        private const string _deploymentTypeDescription = "Enter the Type to use";
        private const string _deploymentTypeAlias = "-TY";
        private const DeploymentType _deploymentTypeDefaultValue = DeploymentType.WMI;

        private const string _localPathName = "--LocalPath";
        private const string _localPathDescription = "Enter the Path to the local File";
        private const string _localPathAlias = "-LPA";
        private const bool _localPathIsRequired = true;

        private const string _destinationPathName = "--DestinationPath";
        private const string _destinationPathDescription = "Enter the Path to the destination File";
        private const string _destinationPathAlias = "-DPA";
        private const bool _destinationPathIsRequired = true;

        private const string _remoteMachineName = "--IP";
        private const string _remoteMachineDescription = "Enter the remote IP from the machine";
        private const string _remoteMachineAlias = "-I";
        private const bool _remoteMachineIsRequired = true;

        private const string _remoteMachineUsernameName = "--User";
        private const string _remoteMachineUsernameDescription = "Enter the remote Username from the machine";
        private const string _remoteMachineUsernameAlias = "-U";
        private const bool _remoteMachineUsernameIsRequired = true;

        private const string _remoteMachinePasswordName = "--Password";
        private const string _remoteMachinePasswordDescription = "Enter the remote Password for the user from the machine";
        private const string _remoteMachinePasswordAlias = "-P";
        private const bool _remoteMachinePasswordIsRequired = true;

        private const string _remoteMachineDomainName = "--Domain";
        private const string _remoteMachineDomainDescription = "Enter the remote Domain to login";
        private const string _remoteMachineDomainAlias = "-D";

        private const string _remoteMachineTimeoutName = "--Timeout";
        private const string _remoteMachineTimeoutDescription = "Enter the remote Timeout to wait max";
        private const string _remoteMachineTimeoutAlias = "-T";
        private const int _remoteMachineTimeoutDefaultValue = 5;

        private readonly Logger _logger;

        internal DownloadFile(Logger Logger)
        {
            _logger = Logger;
        }
    }
}
