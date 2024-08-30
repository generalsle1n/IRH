using IRH.ProcessElevation.Model;
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
        internal async Task<string> GetSPNFromCurrent()
        {
            Domain CurrentDomain = Domain.GetCurrentDomain();
            string CurrentDomainName = CurrentDomain.Name;
            string CurrentDomainControllerName = CurrentDomain.PdcRoleOwner.Name;

            SecurityHandle Handle = new SecurityHandle(0);
            SecurityInteger Integer = new SecurityInteger(0);

            DomainInteractionInterop.AcquireCredentialsHandle(
                null, 
                "Kerberos", 
                DomainInteractionInterop.SECPKG_CRED_OUTBOUND, 
                IntPtr.Zero, 
                IntPtr.Zero, 
                0, 
                IntPtr.Zero, 
                ref Handle, 
                ref Integer
                );

            return CurrentDomainControllerName;
        }
    }
}
