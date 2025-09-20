using Serilog.Core;
using System.CommandLine;

namespace IRH.Commands.Azure.AuditLog.Exchange
{
    internal class ExchangeAudit
    {
        private readonly Logger _logger;

        private const string _commandName = "-Exchange";
        private const string _commandDescription = "Operate with the Exchange System from Microsoft";

        //private const string _filterOnParameter = "-FP";
        //private const string _filterOnParameterDescription = "Filter on Parameternames (Displayfilter), Wildcards are supported (This Setting works only on Printlevel Info and above) its also possible to enter multiple values seperated by whitespace";
        //private const string _filterOnParameterAlias = "--FilterParameter";

        //private const string _filterOnParameterValue = "-FV";
        //private const string _filterOnParameterValueDescription = "Filter on Paramtervalue (Datafilter): Syntax --> ParamterName:ParameterValue (Example: Id:241af6fe-955d-4884-b27d-08dc93695d85), if you specify multiple serpated by whitespace it have an AND Operator, there is an Wildcard Support for the parametervalue";
        //private const string _filterOnParameterValueAlias = "--FilterValue";

        internal ExchangeAudit(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            ExchangeModifiedAudit ExchangeAuditCommand = new ExchangeModifiedAudit(_logger);
            Command ExchangeCommand = ExchangeAuditCommand.CreateCommand(RootCommand);

            ExchangeUserAudit LoginAuditCommand = new ExchangeUserAudit(_logger);
            Command LoginCommand = LoginAuditCommand.CreateCommand(RootCommand);

            Command.Add(ExchangeCommand);
            Command.Add(LoginCommand);

            return Command;
        }
    }
}
