using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.LDAPMonitor
{
    internal class ObjectChangedEventArgs : EventArgs
    {
        public SearchResultEntry Result { get; set; }

        public ObjectChangedEventArgs(SearchResultEntry entry)
        {
            Result = entry;
        }
    }
}
