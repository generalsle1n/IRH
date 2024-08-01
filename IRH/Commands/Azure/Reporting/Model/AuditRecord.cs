using Microsoft.Graph.Beta.Models.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.Azure.Reporting.Model
{
    public class AuditRecord
    {
        public AuditLogRecord Record { get; set; }
        public List<KeyValuePair<string, string>> ExtensionData { get; set; }
    }
}
