using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.Azure.AuditLog.Model
{
    internal class AuditProcessorRule
    {
        internal AuditRawRule RawRule { get; set; }
        internal AuditRegexRule RegexRule { get; set; }
    }
}
