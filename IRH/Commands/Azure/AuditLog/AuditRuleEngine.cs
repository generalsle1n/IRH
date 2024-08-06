using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IRH.Commands.Azure.AuditLog.Model;
using IRH.Commands.Azure.Helper;
using Microsoft.Graph.Beta.Models.Security;
using Serilog.Core;

namespace IRH.Commands.Azure.AuditLog
{
    internal class AuditRuleEngine
    {
        private List<AuditProcessorRule> _rules;
        private readonly Logger _logger;
        private const string _ruleSeperator = ":";

        internal AuditRuleEngine(string[] RuleText, Logger Logger)
        {
            _logger = Logger;

            _rules = new List<AuditProcessorRule>();

            foreach (string SingleRule in RuleText)
            {
                string[] Splitted = SingleRule.Split(_ruleSeperator);

                _rules.Add(new AuditProcessorRule()
                {
                    RawRule = new AuditRawRule()
                    {
                        ParamterNameFilter = Splitted[0],
                        ParamterValueFilter = Splitted[1]
                    },
                    RegexRule = new AuditRegexRule()
                    {
                        ParamterNameFilter = CreateRegex(Splitted[0]),
                        ParamterValueFilter = CreateRegex(Splitted[1])
                    }
                });

                _logger.Information($"Loaded {SingleRule} Rule into Engine");
            }

            _logger.Information($"{_rules.Count} Rules loaded");
        }

        internal async Task<bool> ProcessAudit(AuditLogRecord Record)
        {
            List<bool> AllResult = new List<bool>();

            foreach (AuditProcessorRule SingleRule in _rules)
            {
                bool SearchResult = false;

                SearchResult = await IsMatchingRecordInfoLevel(Record, SingleRule);

                if(!SearchResult)
                {
                    SearchResult = await IsMatchingRecordAuditLevel(Record, SingleRule);

                    if (!SearchResult)
                    {
                        SearchResult = await IsMatchingRecordExpandedLevel(Record, SingleRule);
                    }
                }

                AllResult.Add(SearchResult);

            }

            bool Result = AllResult.All(filter => filter == true);

            return Result;
        }

        internal async Task<bool> IsMatchingRecordInfoLevel(AuditLogRecord Record, AuditProcessorRule Rule)
        {
            bool SingleResult = false;

            PropertyInfo[] AllProperties = Record.GetType().GetProperties();

            IEnumerable<PropertyInfo> Search = AllProperties.Where(filter => filter.Name.Equals(Rule.RawRule.ParamterNameFilter));

            _logger.Verbose($"Evaluted {AllProperties.Length} Properties for Object {Record.Id}");

            if (Search.Count() > 0)
            {
                PropertyInfo FilterdProperty = Search.First();
                string PropertyValue = FilterdProperty.GetValue(Record) as string;

                _logger.Verbose($"Searching {FilterdProperty.Name} in {Record.Id}");

                if (await MatchStringToRegex(PropertyValue, Rule.RegexRule.ParamterValueFilter))
                {
                    SingleResult = true;
                }

                _logger.Verbose($"Match for {FilterdProperty.Name}: {SingleResult}");
            }

            return SingleResult;
        }

        internal async Task<bool> IsMatchingRecordAuditLevel(AuditLogRecord Record, AuditProcessorRule Rule)
        {
            bool SingleResult = false;

            IAsyncEnumerable<KeyValuePair<string, object>> Search = Record.AuditData.AdditionalData.ToAsyncEnumerable().WhereAwait(async filter =>
            {
                return (filter.Key.Equals(Rule.RawRule.ParamterNameFilter) && await MatchStringToRegex(filter.Value.ToString(), Rule.RegexRule.ParamterValueFilter));
            });

            _logger.Verbose($"Evaluted {Record.AuditData.AdditionalData.Count} Properties for Object {Record.Id}");

            if (await Search.CountAsync() > 0)
            {
                SingleResult = true;
                _logger.Verbose($"Match for {(await Search.FirstAsync()).Key}: {SingleResult}");
            }

            return SingleResult;
        }

        internal async Task<bool> IsMatchingRecordExpandedLevel(AuditLogRecord Record, AuditProcessorRule Rule)
        {
            bool SingleResult = false;

            _logger.Verbose($"Try to expand object{Record.Id} for further search");

            List<KeyValuePair<string, string>> Expanded = await UnTypedExtractor.ExtractUntypedDataFromAuditLogRecord(Record);

            IAsyncEnumerable<KeyValuePair<string, string>> SearchForExpand = Expanded.ToAsyncEnumerable().WhereAwait(async filter =>
            {
                return filter.Key.Equals(Rule.RawRule.ParamterNameFilter) && await MatchStringToRegex(filter.Value as string, Rule.RegexRule.ParamterValueFilter);
            });

            if (await SearchForExpand.CountAsync() > 0)
            {
                SingleResult = true;
                _logger.Verbose($"Match for Expanded {Rule.RawRule.ParamterNameFilter}: {SingleResult}");
            }

            return SingleResult;
        }

        internal Regex CreateRegex(string Input)
        {
            string CurrentPattern = $"^{Input.Replace("*", ".*")}$";
            return new Regex(CurrentPattern, RegexOptions.IgnoreCase);
        }

        internal async Task<bool> MatchStringToRegex(string Value, Regex Regex)
        {
            bool Matched = false;

            Match Match = Regex.Match(Value);
            if (Match.Success)
            {
                Matched = true;
            }

            return Matched;
        }
    }
}
