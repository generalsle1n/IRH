using IRH.Commands.SetupDeployment.Types;
using Serilog.Core;
using System.CommandLine;

namespace IRH.Commands.SetupDeployment
{
    internal class SetupDeployment
    {
        private const string _commandName = "-D";
        private const string _commandDescription = "Deploy an Binary to multiple PCs";

        private const string _binaryPathName = "-BP";
        private const string _binaryPathDescription = "Enter the Path to the Binary to Deploy";
        private const string _binaryPathAlias = "--Path";
        private const bool _binaryPathIsRequired = true;

        private const string _userName = "-U";
        private const string _userDescription = "Enter the Username to connect";
        private const string _userNameAlias = "--User";
        private const bool _userIsRequired = true;

        private const string _passwordName = "-P";
        private const string _passwordDescription = "Enter the password from the user";
        private const string _passwordNameAlias = "--Password";
        private const bool _passwordIsRequired = true;

        private const string _computerName = "-C";
        private const string _computerDescription = "The PCs where the binary should be deployed (Can be comma seperated)";
        private const string _computerNameAlias = "--PC";
        private const bool _computerIsRequired = true;

        private const string _deploymentTypeName = "-T";
        private const string _deploymentTypeDescription = "The Method to use to connect to the pcs";
        private const string _deploymentTypeAlias = "--Type";
        private const SetupType _deploymentTypeDefaultValue = SetupType.WinRM;

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string> BinaryPath = new Option<string>(name: _binaryPathName, description: _binaryPathDescription);
            Option<string> Username = new Option<string>(name: _userName, description: _userDescription);
            Option<string> Password = new Option<string>(name: _passwordName, description: _passwordDescription);
            Option<string> Computer = new Option<string>(name: _computerName, description: _computerDescription);
            Option<SetupType> DeploymentType = new Option<SetupType>(name: _deploymentTypeName, description: _deploymentTypeDescription);

            BinaryPath.AddAlias(_binaryPathAlias);
            Username.AddAlias(_userNameAlias);
            Password.AddAlias(_passwordNameAlias);
            Computer.AddAlias(_computerNameAlias);
            DeploymentType.AddAlias(_deploymentTypeAlias);

            BinaryPath.IsRequired = _binaryPathIsRequired;
            Username.IsRequired = _userIsRequired;
            Password.IsRequired = _passwordIsRequired;
            Computer.IsRequired = _computerIsRequired;

            DeploymentType.SetDefaultValue(_deploymentTypeDefaultValue);

            Command.AddOption(BinaryPath);
            Command.AddOption(Username);
            Command.AddOption(Password);
            Command.AddOption(Computer);
            Command.AddOption(DeploymentType);

            Command.SetHandler((BinaryPathValue, UsernameValue, PasswordValue, ComputerValue, DeploymentTypeValue) =>
            {
                

            }, BinaryPath, Username, Password, Computer, DeploymentType);

            return Command;
        }
    }
}
