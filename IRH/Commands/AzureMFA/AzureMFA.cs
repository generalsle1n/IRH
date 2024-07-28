using Serilog.Core;
using System.CommandLine;
using System.DirectoryServices.Protocols;
using System.Net;

namespace IRH.Commands.LDAPMonitor
{
    internal class AzureMFA
    {
        private const string _commandName = "-AMFA";
        private const string _commandDescription = "Get All Users and there MFA Count and Print";

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by comma";
        private const string _filterOnGroupAlias = "--Group";

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
