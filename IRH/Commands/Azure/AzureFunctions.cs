using IRH.Commands.Azure.MFA;
using IRH.Commands.Azure.AuditLog;
using Serilog.Core;
using System.CommandLine;
using IRH.Commands.Azure.Session;
using IRH.Lib.Model.Azure.Auth;
//using IRH.Commands.Azure.MCU;

namespace IRH.Commands.Azure
{
    internal class AzureFunctions
    {
        private const string _commandName = "-Azure";
        private const string _commandDescription = "All available Azure Commands";

        internal const string _publicAppID = "-A";
        private const string _publicAppIDDescription = "Enter the ID of the App ID";
        private const string _publicAppIDAlias = "--AppID";
        private const bool _publicAppIDIsRequired = true;
        private const string _publicAppIDDefaultValue = "c0849608-c8b9-4e86-b37d-fce972a0a7f6";

        internal const string _publicTenantID = "-T";
        private const string _publicTenantIDDescription = "Enter the ID of the Tenant ID (In the default you dont need to change this)";
        private const string _publicTenantIDAlias = "--Tenant";
        private const string _publicTenantIDDefaultValue = "common";

        internal const string _authClientProvider = "-AU";
        private const string _authClientProviderDescription = "Enter the the process how you want to authenticate";
        private const string _authClientProviderAlias = "--AuthType";
        private const AuthType _authClientProviderDefaultValue = AuthType.DeviceCode;

        private readonly Logger _logger;

        internal AzureFunctions(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string> AppID = new Option<string>(name: _publicAppID, aliases: _publicAppIDAlias)
            {
                Description = _publicAppIDDescription,
                Required = _publicAppIDIsRequired,
                DefaultValueFactory = (result) => _publicAppIDDefaultValue,
                Recursive = true
            };

            Option<string> TenantID = new Option<string>(name: _publicTenantID, aliases: _publicTenantIDAlias)
            {
                Description = _publicTenantIDDescription,
                DefaultValueFactory = (result) => _publicTenantIDDefaultValue,
                Recursive = true
            };

            Option<AuthType> AuthType = new Option<AuthType>(name: _authClientProvider, aliases: _authClientProviderAlias) 
            {
                Description = _authClientProviderDescription,
                DefaultValueFactory = (result) => _authClientProviderDefaultValue,
                Recursive = true
            };

            Command.Options.Add(AppID);
            Command.Options.Add(TenantID);
            Command.Options.Add(AuthType);

            //Command.AddGlobalOption(AppID);
            //Command.AddGlobalOption(TenantID);
            //Command.AddGlobalOption(AuthType);

            AzureMFACommand AzureMFACommand = new AzureMFACommand(_logger);
            Command AzureMFA = AzureMFACommand.CreateCommand(RootCommand);

            AzureSessionCommand AzureSessionCommand = new AzureSessionCommand(_logger);
            Command AzureSession = AzureSessionCommand.CreateCommand(RootCommand);

            //AzureAuditLog AzureAuditLogCommand = new AzureAuditLog(_logger);
            //Command AzureAuditLog = AzureAuditLogCommand.CreateCommand(RootCommand);

            //AzureMailCleanupCommand AzureMailCleanupCommand = new AzureMailCleanupCommand(_logger);
            //Command AzureMCU = AzureMailCleanupCommand.CreateCommand(RootCommand);


            Command.Add(AzureMFA);
            Command.Add(AzureSession);
            //Command.AddCommand(AzureAuditLog);
            //Command.Add(AzureMCU);

            return Command;
        }
    }
}
