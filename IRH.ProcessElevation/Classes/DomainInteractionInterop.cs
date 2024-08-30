using IRH.ProcessElevation.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Classes
{
    internal class DomainInteractionInterop
    {
        internal static int SECPKG_CRED_OUTBOUND = 2;

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int AcquireCredentialsHandle(
            string SecurityChar, //SEC_CHAR*
            string PackageType, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int IsInUse,
            IntPtr AuthID,//_LUID AuthenticationID,//pvLogonID,//PLUID
            IntPtr AuthData,//PVOID
            int SecurityKey, //SEC_GET_KEY_FN
            IntPtr KeyArgument, //PVOID
            ref SecurityHandle HandleKey, //SecHandle //PCtxtHandle ref
            ref SecurityInteger ExpiryDate  //PTimeStamp //TimeStamp ref
        );
        );
    }
}
