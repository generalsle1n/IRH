using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Classes
{
    internal class DomainInteraction
    {
        private extern AcquireCredentialsHandle
        internal async Task<string> GetSPNFromCurrent()
        {
            Domain CurrentDomain = Domain.GetCurrentDomain();
            string CurrentDomainName = CurrentDomain.Name;
            string CurrentDomainControllerName = CurrentDomain.PdcRoleOwner.Name;
            //string DomainController = Domain.
            return CurrentDomainControllerName;
            //var domainController = Networking.GetDCName(domain);
        }
    }
}
