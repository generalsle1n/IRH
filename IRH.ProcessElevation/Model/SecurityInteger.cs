using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal struct SecurityInteger
    {
        internal uint LowPart;
        internal int HighPart;

        internal SecurityInteger(int NotUsed)
        {
            LowPart = 0;
            HighPart = 0;
        }
    }
}
