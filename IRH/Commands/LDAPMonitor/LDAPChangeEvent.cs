using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.LDAPMonitor
{
    internal class LDAPChangeEvent : EventArgs
    {
        internal LDAPChangeEvent(SearchResultEntry entry)
        {
            Result = entry;
        }

        internal SearchResultEntry Result { get; set; }
    }
}
