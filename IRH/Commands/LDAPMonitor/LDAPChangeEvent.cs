using System.DirectoryServices.Protocols;

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
