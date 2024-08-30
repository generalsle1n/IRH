using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal class SecurityHandle
    {
        internal IntPtr LowPart;
        internal IntPtr HighPart;

        internal SecurityHandle(int NotUsed)
        {
            LowPart = HighPart = IntPtr.Zero;
        }
    }
}
