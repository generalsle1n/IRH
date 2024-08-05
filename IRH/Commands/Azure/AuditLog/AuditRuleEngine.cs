using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Graph.Beta.Models.Security;
using Serilog.Core;

namespace IRH.Commands.Azure
{
    internal class AuditRuleEngine
    {
        private List<KeyValuePair<string, string>> _rules;
        private readonly Logger _logger;
        private const string _ruleSeperator = ":";

        internal AuditRuleEngine(string[] RuleText, Logger Logger)
        {
            _logger = Logger;
            _rules = new List<KeyValuePair<string, string>>();

            foreach(string SingleRule in RuleText)
            {
                string[] Splitted = SingleRule.Split(_ruleSeperator);
                _rules.Add(new KeyValuePair<string, string>(Splitted[0], Splitted[1]));

                _logger.Information($"Loaded {SingleRule} Rule into Engine");
            }

            _logger.Information($"{_rules.Count} Rules loaded");
        }

        internal async Task<bool> ProcessAudit(AuditLogRecord Record)
        {
            PropertyInfo[] AllProperties = Record.GetType().GetProperties();

            List<bool> AllResult = new List<bool>();

            foreach(KeyValuePair<string, string> SingleRule in _rules)
            {
                bool SingleResult = false;

                IEnumerable<PropertyInfo> Search = AllProperties.Where(filter => filter.Name.Equals(SingleRule.Key));

                _logger.Verbose($"Evaluted {AllProperties.Length} Properties for Object {Record.Id}");

                if(Search.Count() > 0)
                {
                    PropertyInfo FilterdProperty = Search.First();
                    string PropertyValue = FilterdProperty.GetValue(Record) as string;

                    _logger.Verbose($"Searching {FilterdProperty.Name} in {Record.Id}");

                    if (PropertyValue.Equals(SingleRule.Value))
                    {
                        SingleResult = true;
                    }

                    _logger.Verbose($"Match for {FilterdProperty.Name}: {SingleResult}");
                }

                AllResult.Add(SingleResult);
            }

            bool Result = AllResult.All(filter => filter == true);

            return Result;
        }
    }
}
