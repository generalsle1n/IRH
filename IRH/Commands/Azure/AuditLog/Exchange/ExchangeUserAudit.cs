using IRH.Commands.Azure.Helper;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models.Security;
using Serilog.Core;
using System.CommandLine;
using IRH.Lib.Class.Azure.Audit;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Class.Azure.Auth;

namespace IRH.Commands.Azure.AuditLog.Exchange
{
    internal class ExchangeUserAudit
    {
        private const string _commandName = "-User";
        private const string _commandDescription = "Get all Audit Logs for Exchange an single Exchange User";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = new string[] { "Directory.Read.All", "AuditLogsQuery.Read.All" };

        private const string _userLogin = "-UL";
        private const string _userLoginDescription = "Enter the Userlogin Name (UPN Format), you can provide multiple user logins seperated by whitespace";
        private const string _userLoginAlias = "--Start";
        private const bool _userLoginIsRequired = true;

        private const string _defaultActivities = "-AC";
        private const string _defaultActivitiesDescription = "Enter the Default Activities that should be searched in the Audit Logs (Seperated By Whitespace)";
        private const string _defaultActivitiesAlias = "--Activities";
        private string[] _defaultActivitiesDefaultValue = new string[] { "send", "mailboxlogin", "sendonbehalf", "harddelete", "movetodeleteditems", "move", "sendas", "softdelete", "add-mailboxpermission", "remove-mailboxpermission", "addfolderpermissions", "modifyfolderpermissions" };

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

        //private const string _globalAppIDName = "A";
        //private const string _globalTenantIDName = "T";
        //private const string _globalAuthClientProviderName = "AU";
        //private const string _globalFilterParamterName = "FP";
        //private const string _globalFilterValueName = "FV";
        //private const string _globalStartDateName = "S";
        //private const string _globalEndDateName = "E";

        private readonly Logger _logger;

        internal ExchangeUserAudit(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, aliases: _permissionScopesAlias)
            {
                Description = _permissionScopesDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => _permissionScopesDefaultValue,
            };

            Option<string[]> UserLogin = new Option<string[]>(name: _userLogin, aliases: _userLoginAlias)
            {
                Description = _userLoginDescription,
                Required = _userLoginIsRequired,
                AllowMultipleArgumentsPerToken = true,
            };

            Option<string[]> Activities = new Option<string[]>(name: _defaultActivities, aliases: _defaultActivitiesAlias)
            {
                Description = _defaultActivitiesDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => _defaultActivitiesDefaultValue,
            };

            Option<int> WaitTime = new Option<int>(name: _waitQueryTime, aliases: _waitQueryTimeAlias)
            {
                Description = _waitQueryTimeDescription,
                DefaultValueFactory = (result) => _waitQueryTimeDefaultValue,
            };

            Option<ReportType> ReportTypeOption = new Option<ReportType>(name: _reportType, aliases: _reportTypeAlias)
            {
                Description = _reportTypeDescription,
                DefaultValueFactory = (result) => _reportTypeDefaultValue,
            };

            Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, aliases: _printLevelAlias)
            {
                Description = _printLevelDescription,
                DefaultValueFactory = (result) => _printLevelDefaultValue,
            };

            Option<string> ExistingQuery = new Option<string>(name: _exisitingQuery, aliases: _exisitingQueryAlias)
            {
                Description = _exisitingQueryDescription
            };

            Command.Options.Add(Scopes);
            Command.Options.Add(UserLogin);
            Command.Options.Add(Activities);
            Command.Options.Add(WaitTime);
            Command.Options.Add(ReportTypeOption);
            Command.Options.Add(PrintLevel);
            Command.Options.Add(ExistingQuery);

            Command.SetAction(async parseResult =>
            {
                AzureAuth Auth = new AzureAuth(_logger);
                AuditHelper Helper = new AuditHelper(_logger);
                AzureAudit AzureAudit = new AzureAudit(_logger);

                GraphServiceClient Client = Auth.GetClientBeta(
                    parseResult.GetRequiredValue<string>(AzureFunctions._publicAppID),
                    parseResult.GetRequiredValue<string>(AzureFunctions._publicTenantID),
                    parseResult.GetRequiredValue(Scopes),
                    parseResult.GetRequiredValue<AuthType>(AzureFunctions._authClientProvider)
                    );

                AuditLogQuery CreatedQuery;

                if (parseResult.GetValue(ExistingQuery) is not null)
                {
                    CreatedQuery = await AzureAudit.GetQueryFromName(Client, parseResult.GetRequiredValue(ExistingQuery));
                }
                else
                {
                    CreatedQuery = await AzureAudit.CreateQuery(
                        Client,
                        parseResult.GetRequiredValue<DateTime>(AzureAuditLog._startDate),
                        parseResult.GetRequiredValue<DateTime>(AzureAuditLog._endDate),
                        parseResult.GetRequiredValue(Activities),
                        parseResult.GetRequiredValue(UserLogin)
                   );
                }

                CreatedQuery = await AzureAudit.WaitOnQuery(
                    Client,
                    CreatedQuery,
                    parseResult.GetRequiredValue(WaitTime)
                    );

                AuditLogRecordCollectionResponse Result = await AzureAudit.GetResultFromQuery(Client, CreatedQuery);

                switch (parseResult.GetRequiredValue(ReportTypeOption))
                {
                    case ReportType.CLI:
                        await Helper.PrintResult(Result, parseResult.GetRequiredValue(PrintLevel), parseResult.GetRequiredValue<string[]>(AzureAuditLog._filterOnParameter), parseResult.GetRequiredValue<string[]>(AzureAuditLog._filterOnParameterValue));
                        break;
                    case ReportType.Json:
                        await Helper.ExportToJson(Result);
                        break;
                    case ReportType.CLIAndJson:
                        await Helper.PrintResult(Result, parseResult.GetRequiredValue(PrintLevel), parseResult.GetRequiredValue<string[]>(AzureAuditLog._filterOnParameter), parseResult.GetRequiredValue<string[]>(AzureAuditLog._filterOnParameterValue));
                        await Helper.ExportToJson(Result);
                        break;
                }
            });

            return Command;
        }
    }
}
