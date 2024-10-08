﻿using IRH.Commands.Azure.Reporting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Serilog.Core;
using System.CommandLine;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models.Security;
using System.CommandLine.Parsing;
using IRH.Commands.Azure.Auth;
using IRH.Commands.Azure.Helper;

namespace IRH.Commands.Azure.AuditLog.Login
{
    internal class LoginAudit
    {
        private const string _commandName = "-Login";
        private const string _commandDescription = "Get All Audit Logs for Login Specific Things";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = new string[] { "Directory.Read.All", "AuditLogsQuery.Read.All" };

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
        private string[] _defaultActivitiesDefaultValue = new string[] { "MailboxLogin", "UserLoggedIn", "UserLoginFailed" };

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

        private const string _globalAppIDName = "A";
        private const string _globalTenantIDName = "T";
        private const string _globalAuthClientProviderName = "AU";
        private const string _globalFilterParamterName = "FP";
        private const string _globalFilterValueName = "FV";

        private readonly Logger _logger;

        internal LoginAudit(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
            Option<DateTime> StartDate = new Option<DateTime>(name: _startDate, description: _startDateDescription);
            Option<DateTime> EndDate = new Option<DateTime>(name: _endDate, description: _endDateDescription);
            Option<string[]> Activities = new Option<string[]>(name: _defaultActivities, description: _defaultActivitiesDescription);
            Option<int> WaitTime = new Option<int>(name: _waitQueryTime, description: _waitQueryTimeDescription);
            Option<ReportType> ReportTypeOption = new Option<ReportType>(name: _reportType, description: _reportTypeDescription);
            Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, description: _printLevelDescription);
            Option<string> ExistingQuery = new Option<string>(name: _exisitingQuery, description: _exisitingQueryDescription);

            Scopes.AllowMultipleArgumentsPerToken = true;
            Activities.AllowMultipleArgumentsPerToken = true;

            Scopes.AddAlias(_permissionScopesAlias);
            StartDate.AddAlias(_startDateAlias);
            EndDate.AddAlias(_endDateAlias);
            Activities.AddAlias(_defaultActivitiesAlias);
            WaitTime.AddAlias(_waitQueryTimeAlias);
            ReportTypeOption.AddAlias(_reportTypeAlias);
            PrintLevel.AddAlias(_printLevelAlias);
            ExistingQuery.AddAlias(_exisitingQueryAlias);

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            Activities.SetDefaultValue(_defaultActivitiesDefaultValue);
            WaitTime.SetDefaultValue(_waitQueryTimeDefaultValue);
            StartDate.SetDefaultValue(_startDateDefaultValue);
            EndDate.SetDefaultValue(_endDateDefaultValue);
            ReportTypeOption.SetDefaultValue(_reportTypeDefaultValue);
            PrintLevel.SetDefaultValue(_printLevelDefaultValue);

            Command.AddOption(Scopes);
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
                CommandResult AzureCommandResult = Parser.CommandResult.Parent.Parent as CommandResult;
                CommandResult AuditCommandResult = Parser.CommandResult.Parent as CommandResult;

                Option<string> AppID = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalAppIDName)).First() as Option<string>;
                Option<string> TenantID = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalTenantIDName)).First() as Option<string>;
                Option<AuthType> AuthProviderType = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalAuthClientProviderName)).First() as Option<AuthType>;
                Option<string[]> FilterParameter = AuditCommandResult.Command.Options.Where(id => id.Name.Equals(_globalFilterParamterName)).First() as Option<string[]>;
                Option<string[]> FilterValue = AuditCommandResult.Command.Options.Where(id => id.Name.Equals(_globalFilterValueName)).First() as Option<string[]>;

                AzureAuth Auth = new AzureAuth();
                AuditHelper Helper = new AuditHelper(_logger);

                GraphServiceClient Client = Auth.GetClientBeta(
                    Parser.GetValueForOption(AppID),
                    Parser.GetValueForOption(TenantID),
                    Parser.GetValueForOption(Scopes),
                    Parser.GetValueForOption(AuthProviderType)
                    );

                AuditLogQuery CreatedQuery;

                if (Parser.GetValueForOption(ExistingQuery) is not null)
                {
                    CreatedQuery = await Helper.GetQueryFromName(Client, Parser.GetValueForOption(ExistingQuery));
                    if(CreatedQuery is null)
                    {
                        _logger.Warning($"No Query with the Name {Parser.GetValueForOption(ExistingQuery)} found, is there an typo?");
                        Environment.Exit(-1);
                    }
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
                        await Helper.PrintResult(Result, Parser.GetValueForOption(PrintLevel), Parser.GetValueForOption(FilterParameter), Parser.GetValueForOption(FilterValue));
                        break;
                    case ReportType.Json:
                        await Helper.ExportToJson(Result);
                        break;
                    case ReportType.CLIAndJson:
                        await Helper.PrintResult(Result, Parser.GetValueForOption(PrintLevel), Parser.GetValueForOption(FilterParameter), Parser.GetValueForOption(FilterValue));
                        await Helper.ExportToJson(Result);
                        break;
                }
            });

            return Command;
        }
    }
}
