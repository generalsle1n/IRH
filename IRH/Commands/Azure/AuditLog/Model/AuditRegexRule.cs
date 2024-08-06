using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IRH.Commands.Azure.AuditLog.Model
{
    internal class AuditRegexRule
    {
        internal Regex ParamterNameFilter { get; set; }
        internal Regex ParamterValueFilter { get; set; }
    }
}
