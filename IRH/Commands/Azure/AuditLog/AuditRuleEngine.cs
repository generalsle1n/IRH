using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.Azure
{
    internal class AuditRuleEngine
    {
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
