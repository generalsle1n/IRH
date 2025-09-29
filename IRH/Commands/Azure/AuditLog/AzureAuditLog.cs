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

        internal const string _filterOnParameter = "-FP";
        private const string _filterOnParameterDescription = "Filter on Parameternames (Displayfilter), Wildcards are supported (This Setting works only on Printlevel Info and above) its also possible to enter multiple values seperated by whitespace";
        private const string _filterOnParameterAlias = "--FilterParameter";

        internal const string _filterOnParameterValue = "-FV";
        private const string _filterOnParameterValueDescription = "Filter on Paramtervalue (Datafilter): Syntax --> ParamterName:ParameterValue (Example: Id:241af6fe-955d-4884-b27d-08dc93695d85), if you specify multiple serpated by whitespace it have an AND Operator, there is an Wildcard Support for the parametervalue";
        private const string _filterOnParameterValueAlias = "--FilterValue";

        internal const string _startDate = "-S";
        private const string _startDateDescription = "Enter the Start of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _startDateAlias = "--Start";
        private DateTime _startDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);

        internal const string _endDate = "-E";
        private const string _endDateDescription = "Enter the End of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _endDateAlias = "--End";
        private DateTime _endDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day).AddDays(1).AddTicks(-1);

        private readonly Logger _logger;

        internal AzureAuditLog(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> FilterOnParameter = new Option<string[]>(name: _filterOnParameter, aliases: _filterOnParameterAlias)
            {
                Description = _filterOnParameterDescription,
                AllowMultipleArgumentsPerToken = true,
                Recursive = true
            };

            Option<string[]> FilterOnParameterValue = new Option<string[]>(name: _filterOnParameterValue, aliases: _filterOnParameterValueAlias)
            {
                Description = _filterOnParameterValueDescription,
                AllowMultipleArgumentsPerToken = true,
                Recursive = true
            };

            Option<DateTime> StartDate = new Option<DateTime>(name: _startDate, aliases: _startDateAlias)
            {
                Description = _startDateDescription,
                DefaultValueFactory = (result) => _startDateDefaultValue,
                Recursive = true
            };

            Option<DateTime> EndDate = new Option<DateTime>(name: _endDate, aliases: _endDateAlias)
            {
                Description = _endDateDescription,
                DefaultValueFactory = (result) => _endDateDefaultValue,
                Recursive = true
            };

            Command.Options.Add(FilterOnParameter);
            Command.Options.Add(FilterOnParameterValue);
            Command.Options.Add(StartDate);
            Command.Options.Add(EndDate);

            ExchangeAudit ExchangeAuditCommand = new ExchangeAudit(_logger);
            Command ExchangeCommand = ExchangeAuditCommand.CreateCommand(RootCommand);

            LoginAuditCommand LoginAuditCommand = new LoginAuditCommand(_logger);
            Command LoginCommand = LoginAuditCommand.CreateCommand(RootCommand);

            Command.Add(ExchangeCommand);
            Command.Add(LoginCommand);

            return Command;
        }
    }
}
