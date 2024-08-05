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

        private const string _filterOnParameter = "-FP";
        private const string _filterOnParameterDescription = "Filter on Parameternames (Displayfilter), Wildcards are supported (This Setting works only on Printlevel Info and above) its also possible to enter multiple values seperated by whitespace";
        private const string _filterOnParameterAlias = "--FilterParameter";

        private const string _filterOnParameterValue = "-FV";
        private const string _filterOnParameterValueDescription = "Filter on Paramtervalue (Datafilter): Syntax --> ParamterName:FilterValue (Example: *:User1), if you specify multiple serpated by whitespace it have an AND Operator (This Setting works only on Printlevel Info and above)";
        private const string _filterOnParameterValueAlias = "--FilterValue";

        private readonly Logger _logger;

        internal AzureAuditLog(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> FilterOnParameter = new Option<string[]>(name: _filterOnParameter, description: _filterOnParameterDescription);
            Option<string[]> FilterOnParameterValue = new Option<string[]>(name: _filterOnParameterValue, description: _filterOnParameterValueDescription);
            
            FilterOnParameter.AddAlias(_filterOnParameterAlias);
            FilterOnParameterValue.AddAlias(_filterOnParameterValueAlias);

            FilterOnParameter.AllowMultipleArgumentsPerToken = true;
            FilterOnParameterValue.AllowMultipleArgumentsPerToken = true;

            Command.AddGlobalOption(FilterOnParameter);
            Command.AddGlobalOption(FilterOnParameterValue);

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
