using Serilog.Core;
using System.CommandLine;

namespace IRH.Commands.Azure.AuditLog
{
    internal class AzureAuditLog
    {
        private const string _commandName = "-AAudit";
        private const string _commandDescription = "Get All Audit Logs";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = new string[] { "Directory.Read.All", "AuditLogsQuery.Read.All" };

        private const string _publicAppID = "-A";
        private const string _publicAppIDDescription = "Enter the ID of the App ID";
        private const string _publicAppIDAlias = "--AppID";
        private const bool _publicAppIDIsRequired = true;

        private const string _publicTenantID = "-T";
        private const string _publicTenantIDDescription = "Enter the ID of the Tenant ID (In the default you dont need to change this)";
        private const string _publicTenantIDAlias = "--Tenant";
        private const string _publicTenantIDDefaultValue = "common";

        private readonly Logger _logger;

        internal AzureAuditLog(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
            Option<string> AppID = new Option<string>(name: _publicAppID, description: _publicAppIDDescription);
            Option<string> TenantID = new Option<string>(name: _publicTenantID, description: _publicTenantIDDescription);

            AppID.IsRequired = _publicAppIDIsRequired;

            Scopes.AllowMultipleArgumentsPerToken = true;

            Scopes.AddAlias(_permissionScopesAlias);
            AppID.AddAlias(_publicAppIDAlias);
            TenantID.AddAlias(_publicTenantIDAlias);

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            TenantID.SetDefaultValue(_publicTenantIDDefaultValue);

            Command.AddOption(Scopes);
            Command.AddOption(AppID);
            Command.AddOption(TenantID);

            Command.SetHandler(async (ScopesValue, AppIDValue, TenantIDValue) =>
            {
                
            }, Scopes, AppID, TenantID);

            return Command;
        }
    }
}
