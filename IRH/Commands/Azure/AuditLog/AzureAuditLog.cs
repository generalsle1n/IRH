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

namespace IRH.Commands.Azure.AuditLog
{
    internal class AzureAuditLog
    {
        private const string _commandName = "-ARules";
        private const string _commandDescription = "Get All Audit Logs for new TransportRules or Inboxrules";

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
        private const bool _startDateIsRequired = true;

        private const string _endDate = "-E";
        private const string _endDateDescription = "Enter the End of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _endDateAlias = "--End";
        private DateTime _endDateDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day).AddDays(1).AddTicks(-1);

        private const string _defaultActivities = "-AC";
        private const string _defaultActivitiesDescription = "Enter the Default Activities that should be searched in the Audit Logs (Seperated By Whitespace)";
        private const string _defaultActivitiesAlias = "--Activities";
        private string[] _defaultActivitiesDefaultValue = new string[] { "New-TransportRule", "New-InboxRule" };

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

        private const int _timeMultiplyer = 1000;
        private const string _methodToStringName = "ToString";

        private readonly Logger _logger;

        internal AzureAuditLog(Logger Logger)
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

            AppID.IsRequired = _publicAppIDIsRequired;
            StartDate.IsRequired = _startDateIsRequired;

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

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            TenantID.SetDefaultValue(_publicTenantIDDefaultValue);
            Activities.SetDefaultValue(_defaultActivitiesDefaultValue);
            WaitTime.SetDefaultValue(_waitQueryTimeDefaultValue);
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

            Command.SetHandler(async (Context) =>
            {
                ParseResult Parser = Context.ParseResult;
                AzureAuth Auth = new AzureAuth();

                //Set Latest Possbile Date on day
                DateTime Date = Parser.GetValueForOption<DateTime>(EndDate);
                DateTime EndDateValue = new DateTime(Date.Year, Date.Month, Date.Day).AddDays(1).AddTicks(-1);

                GraphServiceClient Client = Auth.GetClientBeta(
                    Parser.GetValueForOption<string>(AppID),
                    Parser.GetValueForOption<string>(TenantID),
                    Parser.GetValueForOption<string[]>(Scopes)
                    );

                AuditLogQuery CreatedQuery = await CreateQuery(
                    Client,
                    Parser.GetValueForOption<DateTime>(StartDate),
                    EndDateValue,
                    Parser.GetValueForOption<string[]>(Activities)
                    );

                CreatedQuery = await WaitOnQuery(
                    Client,
                    CreatedQuery,
                    Parser.GetValueForOption<int>(WaitTime)
                    );

                AuditLogRecordCollectionResponse Result = await GetResultFromQuery(Client, CreatedQuery);
                
                switch (Parser.GetValueForOption<ReportType>(ReportTypeOption))
                {
                    case ReportType.CLI:
                        await PrintResult(Result, Parser.GetValueForOption<ReportPrintLevel>(PrintLevel));
                        break;
                    case ReportType.Json:
                        await ExportToJson(Result);
                        break;
                }
            });

            return Command;
        }

        private async Task<AuditLogQuery> CreateQuery(GraphServiceClient Client, DateTime Start, DateTime End, string[] Activities)
        {
            Guid Id = Guid.NewGuid();

            AuditLogQuery Query = new AuditLogQuery()
            {
                FilterStartDateTime = Start,
                FilterEndDateTime = End,
                OperationFilters = Activities.ToList()
            };
            Query.DisplayName = $"Created by IRH_Scanner {Id}";

            _logger.Information($"Try to Create an Audit Search with activties {string.Join(", ", Activities)} Id:{Id}");

            AuditLogQuery Processed = await Client.Security.AuditLog.Queries.PostAsync(Query);
            return Processed;
        }

        private async Task<AuditLogQuery> WaitOnQuery(GraphServiceClient Client, AuditLogQuery Query, int WaitTime)
        {
            _logger.Information($"Start for Waiting Query (This can take some minutes): {Query.DisplayName}");

            while (Query.Status == AuditLogQueryStatus.NotStarted || Query.Status == AuditLogQueryStatus.Running)
            {
                _logger.Information($"Query not finished, current State: {Query.Status}");
                await Task.Delay(WaitTime * _timeMultiplyer);
                Query = await Client.Security.AuditLog.Queries[Query.Id].GetAsync(a => a.QueryParameters.Expand = new string[] { "*" });
            }

            _logger.Information($"Query finished: {Query.DisplayName}");
            return Query;
        }

        private async Task<AuditLogRecordCollectionResponse> GetResultFromQuery(GraphServiceClient Client, AuditLogQuery Query)
        {
            return await Client.Security.AuditLog.Queries[Query.Id].Records.GetAsync();
        }

        private async Task PrintResult(AuditLogRecordCollectionResponse Result, ReportPrintLevel Level)
        {
            foreach (AuditLogRecord SingleRecord in Result.Value)
            {
                _logger.Information($"User: {SingleRecord.UserPrincipalName} -> {SingleRecord.Operation}");
                if (Level == ReportPrintLevel.Info || Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                {
                    PropertyInfo[] AllProperties = SingleRecord.GetType().GetProperties();
                    IEnumerable<PropertyInfo> AllStringVal = AllProperties.Where(prop => prop.PropertyType.Name.Equals("String"));

                    foreach (PropertyInfo StringVal in AllStringVal)
                    {
                        string Value = (string)StringVal.GetValue(SingleRecord);
                        _logger.Information($" | {StringVal.Name} -> {Value}");
                    }
                    if (Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                    {
                        IEnumerable<KeyValuePair<string, object>> FilterResult = SingleRecord.AuditData.AdditionalData.Where(filter => TestIfToStringIsOverwritten(filter.Value.GetType()));

                        foreach (KeyValuePair<string, object> SingleKey in FilterResult)
                        {
                            _logger.Information($" | | {SingleKey.Key} -> {SingleKey.Value}");
                        }
                        
                        if(Level == ReportPrintLevel.Hacky)
                        {
                            FilterResult = SingleRecord.AuditData.AdditionalData.Where(filter => !TestIfToStringIsOverwritten(filter.Value.GetType()));
                            foreach (KeyValuePair<string, object> SingleKey in FilterResult)
                            {
                                if (SingleKey.Value is UntypedObject)
                                {
                                    List<KeyValuePair<string, string>> ExtractedResult = await UnTypedExtractor.ExtractUnTypedObject(SingleKey.Value as UntypedObject);
                                    foreach(KeyValuePair<string,string> SinglePair in ExtractedResult)
                                    {
                                        _logger.Information($" | | | {SinglePair.Key} -> {SinglePair.Value}");
                                    }
                                }
                                else if (SingleKey.Value is UntypedArray)
                                {
                                    List<KeyValuePair<string, string>> ExtractedResult = await UnTypedExtractor.ExtractUntypedArray(SingleKey.Value as UntypedArray);
                                    foreach (KeyValuePair<string, string> SinglePair in ExtractedResult)
                                    {
                                        _logger.Information($" | | | {SinglePair.Key} -> {SinglePair.Value}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private bool TestIfToStringIsOverwritten(Type Typename)
        {
            bool Result = false;
            try
            {
                MethodInfo Info = Typename.GetMethod(_methodToStringName);
            }
            catch (AmbiguousMatchException Exception)
            {
                Result = true;
            }

            return Result;
        }

        private async Task ExportToJson(AuditLogRecordCollectionResponse Result)
        {
            _logger.Information("Converting List into Json");
            List<AuditRecord> GeneratedResults = new List<AuditRecord>();

            foreach (var ResultRecord in Result.Value)
            {
                GeneratedResults.Add(new AuditRecord
                {
                    Record = ResultRecord,
                    ExtensionData = await UnTypedExtractor.ExtractUntypedDataFromAuditLogRecord(ResultRecord)
                });
            }

            using (MemoryStream Stream = new MemoryStream())
            {
                await JsonSerializer.SerializeAsync(Stream, GeneratedResults);
                string FilePath = Path.Combine(Path.GetTempPath(), Path.GetTempFileName());

                using (FileStream FileStream = new FileStream(FilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    Stream.Position = 0;
                    await Stream.CopyToAsync(FileStream);

                    _logger.Information($"Result saved to {FilePath}");
                }
            }
        }
    }
}
