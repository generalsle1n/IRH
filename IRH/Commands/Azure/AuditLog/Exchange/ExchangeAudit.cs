using IRH.Commands.Azure.Helper;
using IRH.Commands.Azure.Reporting.Model;
using IRH.Commands.AzureMFA.Reporting;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models.Security;
using Microsoft.Kiota.Abstractions.Serialization;
using Serilog.Core;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Reflection;
using System.Text.Json;

namespace IRH.Commands.Azure.AuditLog.Exchange
{
    internal class ExchangeAudit
    {
        private const string _commandName = "-Exchange";
        private const string _commandDescription = "Get All Audit Logs for Exchange Specific Things";

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

        private const string _startDate = "-S";
        private const string _startDateDescription = "Enter the Start of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _startDateAlias = "--Start";
        private DateTime _startDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);

        private const string _endDate = "-E";
        private const string _endDateDescription = "Enter the End of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _endDateAlias = "--End";
        private DateTime _endDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day).AddDays(1).AddTicks(-1);

        private const string _defaultActivities = "-AC";
        private const string _defaultActivitiesDescription = "Enter the Default Activities that should be searched in the Audit Logs (Seperated By Whitespace)";
        private const string _defaultActivitiesAlias = "--Activities";
        private string[] _defaultActivitiesDefaultValue = new string[] { "New-TransportRule", "New-InboxRule", "Set-Mailbox", "Set-TransportRule", "Set-InboxRule" };

        private const string _waitQueryTime = "-QT";
        private const string _waitQueryTimeDescription = "Enter the Value how long to wait between the single query checks (In Seconds)";
        private const string _waitQueryTimeAlias = "--QueryWait";
        private const int _waitQueryTimeDefaultValue = 10;

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLI;

        private const string _printLevel = "-PL";
        private const string _printLevelDescription = "How detailed to be printed";
        private const string _printLevelAlias = "--PrintLevel";
        private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

        private const string _exisitingQuery = "-EQ";
        private const string _exisitingQueryDescription = "Enter the Name of the Existing Query to use the result";
        private const string _exisitingQueryAlias = "--ExisitingQuery";

        private readonly Logger _logger;

        internal ExchangeAudit(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
            Option<string> AppID = new Option<string>(name: _publicAppID, description: _publicAppIDDescription);
            Option<string> TenantID = new Option<string>(name: _publicTenantID, description: _publicTenantIDDescription);
            Option<DateTime> StartDate = new Option<DateTime>(name: _startDate, description: _startDateDescription);
            Option<DateTime> EndDate = new Option<DateTime>(name: _endDate, description: _endDateDescription);
            Option<string[]> Activities = new Option<string[]>(name: _defaultActivities, description: _defaultActivitiesDescription);
            Option<int> WaitTime = new Option<int>(name: _waitQueryTime, description: _waitQueryTimeDescription);
            Option<ReportType> ReportTypeOption = new Option<ReportType>(name: _reportType, description: _reportTypeDescription);
            Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, description: _printLevelDescription);
            Option<string> ExistingQuery = new Option<string>(name: _exisitingQuery, description: _exisitingQueryDescription);

            AppID.IsRequired = _publicAppIDIsRequired;

            Scopes.AllowMultipleArgumentsPerToken = true;
            Activities.AllowMultipleArgumentsPerToken = true;

            Scopes.AddAlias(_permissionScopesAlias);
            AppID.AddAlias(_publicAppIDAlias);
            TenantID.AddAlias(_publicTenantIDAlias);
            StartDate.AddAlias(_startDateAlias);
            EndDate.AddAlias(_endDateAlias);
            Activities.AddAlias(_defaultActivitiesAlias);
            WaitTime.AddAlias(_waitQueryTimeAlias);
            ReportTypeOption.AddAlias(_reportTypeAlias);
            PrintLevel.AddAlias(_printLevelAlias);
            ExistingQuery.AddAlias(_exisitingQueryAlias);

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            TenantID.SetDefaultValue(_publicTenantIDDefaultValue);
            Activities.SetDefaultValue(_defaultActivitiesDefaultValue);
            WaitTime.SetDefaultValue(_waitQueryTimeDefaultValue);
            StartDate.SetDefaultValue(_startDateDefaultValue);
            EndDate.SetDefaultValue(_endDateDefaultValue);
            ReportTypeOption.SetDefaultValue(_reportTypeDefaultValue);
            PrintLevel.SetDefaultValue(_printLevelDefaultValue);

            Command.AddOption(Scopes);
            Command.AddOption(AppID);
            Command.AddOption(TenantID);
            Command.AddOption(StartDate);
            Command.AddOption(EndDate);
            Command.AddOption(Activities);
            Command.AddOption(WaitTime);
            Command.AddOption(ReportTypeOption);
            Command.AddOption(PrintLevel);
            Command.AddOption(ExistingQuery);

            Command.SetHandler(async (Context) =>
            {
                ParseResult Parser = Context.ParseResult;
                AzureAuth Auth = new AzureAuth();
                AuditHelper Helper = new AuditHelper(_logger);

                GraphServiceClient Client = Auth.GetClientBeta(
                    Parser.GetValueForOption(AppID),
                    Parser.GetValueForOption(TenantID),
                    Parser.GetValueForOption(Scopes)
                    );
                AuditLogQuery CreatedQuery;

                if (Parser.GetValueForOption(ExistingQuery) is not null)
                {
                    CreatedQuery = await Helper.GetQueryFromName(Client, Parser.GetValueForOption(ExistingQuery));
                }
                else
                {
                    CreatedQuery = await Helper.CreateQuery(
                    Client,
                    Parser.GetValueForOption(StartDate),
                        Parser.GetValueForOption(EndDate),
                    Parser.GetValueForOption(Activities)
                    );
                }

                CreatedQuery = await Helper.WaitOnQuery(
                    Client,
                    CreatedQuery,
                    Parser.GetValueForOption(WaitTime)
                    );

                AuditLogRecordCollectionResponse Result = await Helper.GetResultFromQuery(Client, CreatedQuery);

                switch (Parser.GetValueForOption(ReportTypeOption))
                {
                    case ReportType.CLI:
                        await Helper.PrintResult(Result, Parser.GetValueForOption(PrintLevel));
                        break;
                    case ReportType.Json:
                        await Helper.ExportToJson(Result);
                        break;
                }
            });

            return Command;
        }
    }
}
