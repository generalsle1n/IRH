using Serilog.Core;
using System.CommandLine;

namespace IRH.Commands.LDAPMonitor
{
    internal class AzureMFA
    {
        private const string _commandName = "-AMFA";
        private const string _commandDescription = "Get All Users and there MFA Count and Print";

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by comma";
        private const string _filterOnGroupAlias = "--Group";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = new string[] { "Directory.Read.All", "UserAuthenticationMethod.Read.All" };

        private const string _publicAppID = "-A";
        private const string _publicAppIDDescription = "Enter the ID of the App ID";
        private const string _publicAppIDAlias = "--AppID";
        private const bool _publicAppIDIsRequired = true;

        private const string _publicTenantID = "-T";
        private const string _publicTenantIDDescription = "Enter the ID of the Tenant ID (In the default you dont need to change this)";
        private const string _publicTenantIDAlias = "--Tenant";
        private const string _publicTenantIDDefaultValue = "common";

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLI;

        private readonly Logger _logger;

        internal AzureMFA(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string> Group = new Option<string>(name: _filterOnGroup, description: _filterOnGroupDescription);
            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
            Option<string> AppID = new Option<string>(name: _publicAppID, description: _publicAppIDDescription);
            Option<string> TenantID = new Option<string>(name: _publicTenantID, description: _publicTenantIDDescription);
            Option<string> ReportType = new Option<string>(name: _reportType, description: _reportTypeDescription);

            AppID.IsRequired = _publicAppIDIsRequired;

            Group.AddAlias(_filterOnGroupAlias);
            Scopes.AddAlias(_permissionScopesAlias);
            AppID.AddAlias(_publicAppIDAlias);
            TenantID.AddAlias(_publicTenantIDAlias);
            ReportType.AddAlias(_reportTypeAlias);

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            TenantID.SetDefaultValue(_publicTenantIDDefaultValue);
            ReportType.SetDefaultValue(_reportTypeDefaultValue);
                
            Command.AddOption(Group);
            Command.AddOption(Scopes);
            Command.AddOption(AppID);
            Command.AddOption(TenantID);
            Command.AddOption(ReportType);

            Command.SetHandler(async (GroupValue, ScopesValue, AppIDValue, TenantIDValue) =>
            {
                DeviceCodeCredentialOptions Options = new DeviceCodeCredentialOptions
                {
                    AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                    ClientId = AppIDValue,
                    TenantId = TenantIDValue,

                    DeviceCodeCallback = (code, cancellation) =>
                    {
                        Console.WriteLine(code.Message);
                        return Task.FromResult(0);
                    },
                };

            }, Group);

            return Command;
        }
    }
}
