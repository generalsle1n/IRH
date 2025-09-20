//using Serilog.Core;
//using System.CommandLine;

//namespace IRH.Commands.Azure.AuditLog.Exchange
//{
//    internal class ExchangeAudit
//    {
//        private readonly Logger _logger;

//        private const string _commandName = "-Exchange";
//        private const string _commandDescription = "Operate with the Exchange System from Microsoft";

//        private const string _filterOnParameter = "-FP";
//        private const string _filterOnParameterDescription = "Filter on Parameternames (Displayfilter), Wildcards are supported (This Setting works only on Printlevel Info and above) its also possible to enter multiple values seperated by whitespace";
//        private const string _filterOnParameterAlias = "--FilterParameter";

//        private const string _filterOnParameterValue = "-FV";
//        private const string _filterOnParameterValueDescription = "Filter on Paramtervalue (Datafilter): Syntax --> ParamterName:ParameterValue (Example: Id:241af6fe-955d-4884-b27d-08dc93695d85), if you specify multiple serpated by whitespace it have an AND Operator, there is an Wildcard Support for the parametervalue";
//        private const string _filterOnParameterValueAlias = "--FilterValue";

//        private const string _startDate = "-S";
//        private const string _startDateDescription = "Enter the Start of the Investigation (Just in Format DD.MM.YYYY)";
//        private const string _startDateAlias = "--Start";
//        private DateTime _startDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);

//        private const string _endDate = "-E";
//        private const string _endDateDescription = "Enter the End of the Investigation (Just in Format DD.MM.YYYY)";
//        private const string _endDateAlias = "--End";
//        private DateTime _endDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day).AddDays(1).AddTicks(-1);

//        internal ExchangeAudit(Logger Logger)
//        {
//            _logger = Logger;
//        }

//        internal Command CreateCommand(RootCommand RootCommand)
//        {
//            Command Command = new Command(name: _commandName, description: _commandDescription);

//            //Option<string[]> FilterOnParameter = new Option<string[]>(name: _filterOnParameter, description: _filterOnParameterDescription);
//            //Option<string[]> FilterOnParameterValue = new Option<string[]>(name: _filterOnParameterValue, description: _filterOnParameterValueDescription);
//            Option<DateTime> StartDate = new Option<DateTime>(name: _startDate, description: _startDateDescription);
//            Option<DateTime> EndDate = new Option<DateTime>(name: _endDate, description: _endDateDescription);

//            //FilterOnParameter.AddAlias(_filterOnParameterAlias);
//            //FilterOnParameterValue.AddAlias(_filterOnParameterValueAlias);
//            StartDate.AddAlias(_startDateAlias);
//            EndDate.AddAlias(_endDateAlias);

//            StartDate.SetDefaultValue(_startDateDefaultValue);
//            EndDate.SetDefaultValue(_endDateDefaultValue);

//            //FilterOnParameter.AllowMultipleArgumentsPerToken = true;
//            //FilterOnParameterValue.AllowMultipleArgumentsPerToken = true;

//            //Command.AddGlobalOption(FilterOnParameter);
//            //Command.AddGlobalOption(FilterOnParameterValue);
//            Command.AddGlobalOption(StartDate);
//            Command.AddGlobalOption(EndDate);

//            ExchangeModifiedAudit ExchangeAuditCommand = new ExchangeModifiedAudit(_logger);
//            Command ExchangeCommand = ExchangeAuditCommand.CreateCommand(RootCommand);

//            ExchangeUserAudit LoginAuditCommand = new ExchangeUserAudit(_logger);
//            Command LoginCommand = LoginAuditCommand.CreateCommand(RootCommand);

//            Command.AddCommand(ExchangeCommand);
//            Command.AddCommand(LoginCommand);
//            return Command;
//        }
//    }
//}
