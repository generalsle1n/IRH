using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using IRH.Commands.Azure.Helper;
using IRH.Commands.Azure.Reporting.Model;
using IRH.Commands.Azure.Reporting;
using Microsoft.Graph.Beta.Models.Security;
using Microsoft.Kiota.Abstractions.Serialization;
using Serilog.Core;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models.Security;
using System.Text.RegularExpressions;

namespace IRH.Commands.Azure.AuditLog
{
    internal class AuditHelper
    {
        private readonly Logger _logger;
        private const string _methodToStringName = "ToString";
        private const int _timeMultiplyer = 1000;
        private const string _tmpFileTypeName = ".tmp";
        private const string _jsonFileTypeName = ".json";

        internal AuditHelper(Logger Logger)
        {
            _logger = Logger;
        }

        internal async Task PrintResult(AuditLogRecordCollectionResponse Result, ReportPrintLevel Level, string[] Filter)
        {
            List<Regex> Regex = await CreateRegexFilter(Filter);

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
                        if(await IsFilterMatching(StringVal.Name, Regex))
                        {
                        _logger.Information($" | {StringVal.Name} -> {Value}");
                    }
                        
                    }
                    if (Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                    {
                        IEnumerable<KeyValuePair<string, object>> FilterResult = SingleRecord.AuditData.AdditionalData.Where(filter => TestIfToStringIsOverwritten(filter.Value.GetType()));

                        foreach (KeyValuePair<string, object> SingleKey in FilterResult)
                        {
                            if(await IsFilterMatching(SingleKey.Key, Regex))
                            {
                            _logger.Information($" | | {SingleKey.Key} -> {SingleKey.Value}");
                        }
                        }

                        if (Level == ReportPrintLevel.Hacky)
                        {
                            FilterResult = SingleRecord.AuditData.AdditionalData.Where(filter => !TestIfToStringIsOverwritten(filter.Value.GetType()));
                            foreach (KeyValuePair<string, object> SingleKey in FilterResult)
                            {
                                if (SingleKey.Value is UntypedObject)
                                {
                                    List<KeyValuePair<string, string>> ExtractedResult = await UnTypedExtractor.ExtractUnTypedObject(SingleKey.Value as UntypedObject);
                                    foreach (KeyValuePair<string, string> SinglePair in ExtractedResult)
                                    {
                                        if(await IsFilterMatching(SinglePair.Key, Regex))
                                        {
                                        _logger.Information($" | | | {SinglePair.Key} -> {SinglePair.Value}");
                                    }
                                }
                                }
                                else if (SingleKey.Value is UntypedArray)
                                {
                                    List<KeyValuePair<string, string>> ExtractedResult = await UnTypedExtractor.ExtractUntypedArray(SingleKey.Value as UntypedArray);
                                    foreach (KeyValuePair<string, string> SinglePair in ExtractedResult)
                                    {
                                        if(await IsFilterMatching(SinglePair.Key, Regex))
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
        }

        internal async Task<bool> IsFilterMatching(string Value, List<Regex> Filter)
        {
            if(Filter.Count == 0)
            {
                return true;
                        }
            else
            {
                bool Matched = false;
                foreach(Regex SingleReg in Filter)
                {
                    Match Match = SingleReg.Match(Value);
                    if (Match.Success)
                    {
                        Matched = true;
                        break;
                    }
                }

                return Matched;
            }
        }

        internal async Task<List<Regex>> CreateRegexFilter (string[] Filter)
        {
            List<Regex> Result = new List<Regex>();
            
            foreach(string Value in Filter)
            {
                string CurrentPattern = $"^{Value.Replace("*", ".*")}$";
                Result.Add(new Regex(CurrentPattern, RegexOptions.IgnoreCase));

                _logger.Information($"Created Filter for {CurrentPattern}");
            }

            return Result;
        }

        internal bool TestIfToStringIsOverwritten(Type Typename)
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

        internal async Task ExportToJson(AuditLogRecordCollectionResponse Result)
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
                string FilePath = Path.Combine(Path.GetTempPath(), Path.GetTempFileName().Replace(_tmpFileTypeName, _jsonFileTypeName));

                using (FileStream FileStream = new FileStream(FilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    Stream.Position = 0;
                    await Stream.CopyToAsync(FileStream);

                    _logger.Information($"Result saved to {FilePath}");
                }
            }
        }

        internal async Task<AuditLogQuery> CreateQuery(GraphServiceClient Client, DateTime Start, DateTime End, string[] Activities)
        {
            Guid Id = Guid.NewGuid();

            AuditLogQuery Query = new AuditLogQuery()
            {
                FilterStartDateTime = Start,
                FilterEndDateTime = End,
                OperationFilters = Activities.ToList()
            };
            Query.DisplayName = $"Created by IRH_Scanner {Id}";

            _logger.Information($"Try to Create an Audit Search with activties {string.Join(", ", Activities)} Id:{Id} and in Timeframe {Start} - {End}");

            AuditLogQuery Processed = await Client.Security.AuditLog.Queries.PostAsync(Query);
            return Processed;
        }

        internal async Task<AuditLogQuery> WaitOnQuery(GraphServiceClient Client, AuditLogQuery Query, int WaitTime)
        {
            _logger.Information($"Start for Waiting Query (This can take some minutes, up to 10min): {Query.DisplayName}");

            while (Query.Status == AuditLogQueryStatus.NotStarted || Query.Status == AuditLogQueryStatus.Running)
            {
                _logger.Information($"Query not finished, current State: {Query.Status}");
                await Task.Delay(WaitTime * _timeMultiplyer);
                Query = await Client.Security.AuditLog.Queries[Query.Id].GetAsync(req => req.QueryParameters.Expand = new string[] { "*" });
            }

            _logger.Information($"Query finished: {Query.DisplayName}");
            return Query;
        }

        internal async Task<AuditLogRecordCollectionResponse> GetResultFromQuery(GraphServiceClient Client, AuditLogQuery Query)
        {
            return await Client.Security.AuditLog.Queries[Query.Id].Records.GetAsync();
        }

        internal async Task<AuditLogQuery> GetQueryFromName(GraphServiceClient Client, string QueryName)
        {
            AuditLogQueryCollectionResponse Collection = await Client.Security.AuditLog.Queries.GetAsync();

            IEnumerable<AuditLogQuery> Result = Collection.Value.Where(item => item.DisplayName.Equals(QueryName));
            if(Result.Count() >= 1)
            {
                return Result.First();
            }
            else
            {
                return null;
            }
        }
    }
}
