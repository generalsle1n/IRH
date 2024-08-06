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
            PropertyInfo[] AllProperties = Record.GetType().GetProperties();

            List<bool> AllResult = new List<bool>();

            foreach (AuditProcessorRule SingleRule in _rules)
            {
                bool SingleResult = false;

                IEnumerable<PropertyInfo> Search = AllProperties.Where(filter => filter.Name.Equals(SingleRule.RawRule.ParamterNameFilter));

                _logger.Verbose($"Evaluted {AllProperties.Length} Properties for Object {Record.Id}");

                if (Search.Count() > 0)
                {
                    PropertyInfo FilterdProperty = Search.First();
                    string PropertyValue = FilterdProperty.GetValue(Record) as string;

                    _logger.Verbose($"Searching {FilterdProperty.Name} in {Record.Id}");

                    if (PropertyValue.Equals(SingleRule.RawRule.ParamterValueFilter))
                    {
                        SingleResult = true;
                    }

                    _logger.Verbose($"Match for {FilterdProperty.Name}: {SingleResult}");
                }
                else
                {
                    IEnumerable<KeyValuePair<string, object>> SearchResult = Record.AuditData.AdditionalData.Where(item => item.Key.Equals(SingleRule.RawRule.ParamterNameFilter));

                    if (SearchResult.Count() > 0)
                    {
                        SingleResult = SingleRule.RawRule.ParamterValueFilter.Equals(SearchResult.First().Value.ToString());
                    }
                    else
                    {
                        _logger.Verbose($"Try to expand object{Record.Id} for further search");
                        List<KeyValuePair<string, string>> Expanded = await UnTypedExtractor.ExtractUntypedDataFromAuditLogRecord(Record);

                        IEnumerable<KeyValuePair<string, string>> SearchForExpand = Expanded.Where(filter => filter.Key.Equals(SingleRule.RawRule.ParamterNameFilter) && filter.Value.Equals(SingleRule.RawRule.ParamterValueFilter));

                        if (SearchForExpand.Count() > 0)
                        {
                            SingleResult = true;
                        }

                        _logger.Verbose($"Match for Expanded {SingleRule.RawRule.ParamterNameFilter}: {SingleResult}");
                    }
                }


                AllResult.Add(SingleResult);
            }

            bool Result = AllResult.All(filter => filter == true);

            return Result;
        }

        internal Regex CreateRegex(string Input)
        {
            string CurrentPattern = $"^{Input.Replace("*", ".*")}$";
            return new Regex(CurrentPattern, RegexOptions.IgnoreCase);
        }
    }
}
