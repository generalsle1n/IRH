using System.Reflection;
using System.Text.Json;
using IRH.Commands.Azure.Reporting.Model;
using Microsoft.Graph.Beta.Models.Security;
using Serilog.Core;
using System.Text.RegularExpressions;
using IRH.Commands.Azure.AuditLog;
using IRH.Lib.Model.Azure.Reporting;

namespace IRH.Commands.Azure.Helper
{
    internal class AuditHelper
    {
        private readonly Logger _logger;
        private const string _methodToStringName = "ToString";
        private const string _tmpFileTypeName = ".tmp";
        private const string _jsonFileTypeName = ".json";

        internal AuditHelper(Logger Logger)
        {
            _logger = Logger;
        }

        internal async Task PrintResult(AuditLogRecordCollectionResponse Result, ReportPrintLevel Level, string[] FilterParameter, string[] FilterValue)
        {
            List<Regex> Regex = await CreateRegexFilter(FilterParameter);
            AuditRuleEngine RuleEngine = new AuditRuleEngine(FilterValue, _logger);

            foreach (AuditLogRecord SingleRecord in Result.Value)
            {
                if (await RuleEngine.ProcessAudit(SingleRecord))
                {
                    await PrintResultBrief(SingleRecord);
                    if (Level == ReportPrintLevel.Info || Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                    {
                        await PrintResultInfo(SingleRecord, Regex);

                        if (Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                        {
                            await PrintResultDetailed(SingleRecord, Regex);

                            if (Level == ReportPrintLevel.Hacky)
                            {
                                await PrintResultHacky(SingleRecord, Regex);
                            }
                        }
                    }
                }
            }
        }

        internal async Task PrintResultBrief(AuditLogRecord SingleRecord)
        {
            _logger.Information($"User: {SingleRecord.UserPrincipalName} -> {SingleRecord.Operation}");
        }

        internal async Task PrintResultInfo(AuditLogRecord SingleRecord, List<Regex> Regex)
        {
            PropertyInfo[] AllProperties = SingleRecord.GetType().GetProperties();
            IEnumerable<PropertyInfo> AllStringVal = AllProperties.Where(prop => prop.PropertyType.Name.Equals("String"));

            foreach (PropertyInfo StringVal in AllStringVal)
            {
                string Value = (string)StringVal.GetValue(SingleRecord);
                if (await IsFilterMatching(StringVal.Name, Regex))
                {
                    _logger.Information($" | {StringVal.Name} -> {Value}");
                }
            }
        }

        internal async Task PrintResultDetailed(AuditLogRecord SingleRecord, List<Regex> Regex)
        {
            IEnumerable<KeyValuePair<string, object>> FilterResult = SingleRecord.AuditData.AdditionalData.Where(filter => TestIfToStringIsOverwritten(filter.Value.GetType()));

            foreach (KeyValuePair<string, object> SingleKey in FilterResult)
            {
                if (await IsFilterMatching(SingleKey.Key, Regex))
                {
                    _logger.Information($" | | {SingleKey.Key} -> {SingleKey.Value}");
                }
            }
        }

        internal async Task PrintResultHacky(AuditLogRecord SingleRecord, List<Regex> Regex)
        {
            IEnumerable<KeyValuePair<string, object>> FilterResult = SingleRecord.AuditData.AdditionalData.Where(filter => !TestIfToStringIsOverwritten(filter.Value.GetType()));

            List<KeyValuePair<string, string>> ExtractedResult = await UnTypedExtractor.ExtractUntypedDataFromAuditLogRecord(SingleRecord);
            foreach (KeyValuePair<string, string> SinglePair in ExtractedResult)
            {
                if (await IsFilterMatching(SinglePair.Key, Regex))
                {
                    _logger.Information($" | | | {SinglePair.Key} -> {SinglePair.Value}");
                }
            }
        }

        internal async Task<bool> IsFilterMatching(string Value, List<Regex> Filter)
        {
            if (Filter.Count == 0)
            {
                return true;
            }
            else
            {
                bool Matched = false;
                foreach (Regex SingleReg in Filter)
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

        internal async Task<List<Regex>> CreateRegexFilter(string[] Filter)
        {
            List<Regex> Result = new List<Regex>();

            foreach (string Value in Filter)
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
    }
}
