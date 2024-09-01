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
            string SecurityChar,
            string PackageType,
            int IsInUse,
            IntPtr AuthID,
            IntPtr AuthData,
            int SecurityKey,
            IntPtr KeyArgument,
            ref SecurityHandle CredHandle,
            ref SecurityInteger ExpiryDate 
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int InitializeSecurityContext(
            ref SecurityHandle CredHandle,
            IntPtr PCContextHandle,
            string TargetName,
            int ContextRequest,
            int Reserved,
            int DataReputation,
            IntPtr SecInput,
            int ReservedData,
            out SecurityHandle NewHandle,
            out SecurityBufferDescription SecurityBufferDescription,
            out uint ManagedContext,
            out SecurityInteger ExpiryDate
        );
    }
}
