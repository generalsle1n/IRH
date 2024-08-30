using IRH.ProcessElevation.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Classes
{
    internal class DomainInteractionInterop
    {
        public static extern int AcquireCredentialsHandle(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID,//PLUID
            IntPtr pAuthData,//PVOID
            int pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SecurityHandle phCredential, //SecHandle //PCtxtHandle ref
            ref SecurityInteger ptsExpiry  //PTimeStamp //TimeStamp ref
        );
    }
}
