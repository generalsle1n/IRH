using Microsoft.Graph.Beta.Models.Security;

namespace IRH.Commands.Azure.Reporting.Model
{
    public class AuditRecord
    {
        public AuditLogRecord Record { get; set; }
        public List<KeyValuePair<string, string>> ExtensionData { get; set; }
    }
}
