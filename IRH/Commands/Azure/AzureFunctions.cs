using IRH.Commands.Azure.MFA;
using IRH.Commands.Azure.AuditLog;
using Serilog.Core;
using System.CommandLine;

namespace IRH.Commands.Azure
{
    internal class AzureFunctions
    {
        private const string _commandName = "-Azure";
        private const string _commandDescription = "All available Azure Commands";

        private readonly Logger _logger;

        internal AzureFunctions(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            AzureMFA AzureMFACommand = new AzureMFA(_logger);
            Command AzureMFA = AzureMFACommand.CreateCommand(RootCommand);

            AzureAuditLog AzureAuditLogCommand = new AzureAuditLog(_logger);
            Command AzureAuditLog = AzureAuditLogCommand.CreateCommand(RootCommand);

            Command.AddCommand(AzureMFA);
            Command.AddCommand(AzureAuditLog);

            return Command;
        }
    }
}
