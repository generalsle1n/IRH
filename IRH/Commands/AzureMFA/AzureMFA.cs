﻿using Serilog.Core;
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

        private readonly Logger _logger;

        internal AzureMFA(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string> Group = new Option<string>(name: _filterOnGroup, description: _filterOnGroupDescription);

            Group.AddAlias(_filterOnGroupAlias);

            Command.SetHandler((GroupValue) =>
            {
                

            }, Group);

            return Command;
        }
    }
}
