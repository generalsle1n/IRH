using IRH.Remote.Commands.General;
using IRH.Remote.Commands.General.Model;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.UploadFile
{
    internal class UploadFile
    {
        private const string _commandName = "--Upload";
        private const string _commandDescription = "Upload an File on an remote Machine";
        private const string _commandAlias = "-UP";

        private const string _deploymentTypeName = "--Type";
        private const string _deploymentTypeDescription = "Enter the Deployment Type to use";
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
        private const int _remoteMachineTimeoutDefaultValue = 10;

        private const string _optionSeperator = "-";
        private const string _defaultRegistryKey = @"SOFTWARE\Microsoft\Windows";

        private readonly Logger _logger;

        internal UploadFile(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(Command Root)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);
            Command.AddAlias(_commandAlias);

            Option<DeploymentType> DeploymentTypeOption = new Option<DeploymentType>(name: _deploymentTypeName, description: _deploymentTypeDescription);
            DeploymentTypeOption.AddAlias(_deploymentTypeAlias);
            DeploymentTypeOption.SetDefaultValue(_deploymentTypeDefaultValue);

            Option<string> LocalPathOption = new Option<string>(name: _localPathName, description: _localPathDescription)
            {
                IsRequired = _localPathIsRequired
            };
            LocalPathOption.AddAlias(_localPathAlias);

            Option<string> DestinationPathOption = new Option<string>(name: _destinationPathName, description: _destinationPathDescription)
            {
                IsRequired = _destinationPathIsRequired
            };
            DestinationPathOption.AddAlias(_destinationPathAlias);

            Option<string> RemoteMachineOption = new Option<string>(name: _remoteMachineName, description: _remoteMachineDescription)
            {
                IsRequired = _remoteMachineIsRequired
            };
            RemoteMachineOption.AddAlias(_remoteMachineAlias);

            Option<string> RemoteMachineUserNameOption = new Option<string>(name: _remoteMachineUsernameName, description: _remoteMachineUsernameDescription)
            {
                IsRequired = _remoteMachineUsernameIsRequired
            };
            RemoteMachineUserNameOption.AddAlias(_remoteMachineUsernameAlias);

            Option<string> RemoteMachinePasswordOption = new Option<string>(name: _remoteMachinePasswordName, description: _remoteMachinePasswordDescription)
            {
                IsRequired = _remoteMachinePasswordIsRequired
            };
            RemoteMachinePasswordOption.AddAlias(_remoteMachinePasswordAlias);

            Option<string> RemoteMachineDomainOption = new Option<string>(name: _remoteMachineDomainName, description: _remoteMachineDomainDescription);
            RemoteMachineDomainOption.AddAlias(_remoteMachineDomainAlias);

            Option<int> RemoteMachineTimeoutOption = new Option<int>(name: _remoteMachineTimeoutName, description: _remoteMachineTimeoutDescription);
            RemoteMachineTimeoutOption.AddAlias(_remoteMachineTimeoutAlias);
            RemoteMachineTimeoutOption.SetDefaultValue(_remoteMachineTimeoutDefaultValue);

            Command.AddOption(DeploymentTypeOption);
            Command.AddOption(LocalPathOption);
            Command.AddOption(DestinationPathOption);
            Command.AddOption(RemoteMachineOption);
            Command.AddOption(RemoteMachineUserNameOption);
            Command.AddOption(RemoteMachinePasswordOption);
            Command.AddOption(RemoteMachineDomainOption);
            Command.AddOption(RemoteMachineTimeoutOption);

            Command.SetHandler(async (Context) =>
            {
                ParseResult Parser = Context.ParseResult;
                CommandResult ExecutionCommandResult = Parser.CommandResult as CommandResult;

                Option<DeploymentType> DeploymentTypeOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_deploymentTypeName.Replace(_optionSeperator, ""))).First() as Option<DeploymentType>;
                Option<string> LocalPathOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_localPathName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<string> DestinationPathOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_destinationPathName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<string> RemoteMachineOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_remoteMachineName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<string> RemoteMachineUserNameOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_remoteMachineUsernameName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<string> RemoteMachinePasswordOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_remoteMachinePasswordName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<string> RemoteMachineDomainOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_remoteMachineDomainName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<int> RemoteMachineTimeoutOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_remoteMachineTimeoutName.Replace(_optionSeperator, ""))).First() as Option<int>;

                switch (Parser.GetValueForOption(DeploymentTypeOption))
                {
                    case DeploymentType.WMI:
                        _logger.Information("WMI Deployment Type is selected");

                        string Domain = Parser.GetValueForOption(RemoteMachineDomainOption) ?? Parser.GetValueForOption(RemoteMachineOption);

                        using (CimSession Session = CimHelper.CreateSession(Parser.GetValueForOption(RemoteMachineOption), Domain, Parser.GetValueForOption(RemoteMachineUserNameOption), Parser.GetValueForOption(RemoteMachinePasswordOption), Parser.GetValueForOption(RemoteMachineTimeoutOption)))
                        {
                            bool ConnectionCheck = Session.TestConnection();

                            if (ConnectionCheck)
                            {
                                _logger.Information($"Connection to {Parser.GetValueForOption(RemoteMachineOption)} established");

                                byte[] FileData = File.ReadAllBytes(Parser.GetValueForOption(LocalPathOption));
                                byte[] Result = ByteArrayHelper.MergeArray(Encoding.UTF8.GetBytes(Parser.GetValueForOption(DestinationPathOption)), FileData);
                                Guid ValueName = Guid.NewGuid();

                                bool Success = RegistryHelper.CreateRegistryValue(Session, _defaultRegistryKey, ValueName.ToString(), Result, _logger, Tree: RegistryTree.HKEY_CURRENT_USER);
                                if (Success)
                                {
                                    string EncodedScript = PowershellHelper.CreateScriptToWriteFileFromRegistry(ValueName.ToString(), _logger);
                                    ProcessHelper.CreatePowershellProcess(Session, EncodedScript, _logger);
                                    RegistryHelper.DeleteRegistryValue(Session, _defaultRegistryKey, ValueName.ToString(), _logger, Tree: RegistryTree.HKEY_CURRENT_USER);
                                }
                                else
                                {
                                    _logger.Error("File upload failed");
                                }
                            }
                            else
                            {
                                _logger.Error($"Connection to {Parser.GetValueForOption(RemoteMachineOption)} with User {Parser.GetValueForOption(RemoteMachineUserNameOption)} and Domain {Domain} failed");
                            }
                        }
                        break;
                    default:
                        _logger.Error("No Deployment Type is selected");
                        break;
                }
            });

            return Command;
        }
    }
}
