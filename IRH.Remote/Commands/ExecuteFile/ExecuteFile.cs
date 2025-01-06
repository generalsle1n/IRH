using IRH.Remote.Commands.General;
using IRH.Remote.Commands.General.Model;
using Microsoft.Management.Infrastructure;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.ExecuteFile
{
    internal class ExecuteFile
    {
        private const string _commandName = "--Execute";
        private const string _commandDescription = "Execute an File on the remote Machine";
        private const string _commandAlias = "-E";

        private const string _deploymentTypeName = "--Type";
        private const string _deploymentTypeDescription = "Enter the Type to use";
        private const string _deploymentTypeAlias = "-TY";
        private const DeploymentType _deploymentTypeDefaultValue = DeploymentType.WMI;

        private const string _executablePathName = "--Path";
        private const string _executablePathDescription = "Enter the Path to the destination executable File";
        private const string _executablePathAlias = "-PA";
        private const bool _executablePathIsRequired = true;

        private const string _argumentName = "--Arguments";
        private const string _argumentDescription = "Enter the Arguments for the executable File";
        private const string _argumentAlias = "-A";

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
        private const string _remoteMachineDomainAlias = "-DO";

        private const string _remoteMachineTimeoutName = "--Timeout";
        private const string _remoteMachineTimeoutDescription = "Enter the remote Timeout to wait max";
        private const string _remoteMachineTimeoutAlias = "-T";
        private const int _remoteMachineTimeoutDefaultValue = 10;

        private const string _optionSeperator = "-";

        private readonly Logger _logger;

        internal ExecuteFile(Logger Logger)
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

            Option<string> ExecutablePathOption = new Option<string>(name: _executablePathName, description: _executablePathDescription)
            {
                IsRequired = _executablePathIsRequired
            };
            ExecutablePathOption.AddAlias(_executablePathAlias);

            Option<string> ArgumentOption = new Option<string>(name: _argumentName, description: _argumentDescription);
            ArgumentOption.AddAlias(_argumentAlias);

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
            Command.AddOption(ExecutablePathOption);
            Command.AddOption(ArgumentOption);
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
                Option<string> ExecutablePathOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_executablePathName.Replace(_optionSeperator, ""))).First() as Option<string>;
                Option<string> ArgumentOption = ExecutionCommandResult.Command.Options.Where(id => id.Name.Equals(_argumentName.Replace(_optionSeperator, ""))).First() as Option<string>;
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
                                
                                bool Success = ProcessHelper.CreateProcess(Session, Parser.GetValueForOption(ExecutablePathOption), Parser.GetValueForOption(ArgumentOption), _logger);

                                if (Success)
                                {
                                    _logger.Information("Start of executable successful!");
                                }
                                else
                                {
                                    _logger.Error("Start of executable failed!");
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
