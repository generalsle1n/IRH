using IRH.Commands.Azure.AuditLog.Exchange;
using IRH.Commands.Azure.AuditLog.Login;
using Serilog.Core;
using System.CommandLine;

namespace IRH.Commands.Azure.AuditLog
{
    internal class AzureAuditLog
    {
        private const string _commandName = "-Audit";
        private const string _commandDescription = "Operate with the Audit System from Microsoft";

        private const string _filterOnAttributes = "-F";
        private const string _filterOnAttributesDescription = "Filter on Parameternames, Wildcards are supported (This Setting works only on Printlevel Info and above)";
        private const string _filterOnAttributesAlias = "--Filter";

        private readonly Logger _logger;

        internal AzureAuditLog(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> FilterOnParameter = new Option<string[]>(name: _filterOnAttributes, description: _filterOnAttributesDescription);
            FilterOnParameter.AddAlias(_filterOnAttributesAlias);

            Command.AddGlobalOption(FilterOnParameter);

            ExchangeAudit ExchangeAuditCommand = new ExchangeAudit(_logger);
            Command ExchangeCommand = ExchangeAuditCommand.CreateCommand(RootCommand);
            
            LoginAudit LoginAuditCommand = new LoginAudit(_logger);
            Command LoginCommand = LoginAuditCommand.CreateCommand(RootCommand);

            Command.AddCommand(ExchangeCommand);
            Command.AddCommand(LoginCommand);
            return Command;
        }
    }
}
