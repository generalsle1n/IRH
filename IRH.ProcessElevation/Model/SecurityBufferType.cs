using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal enum SecurityBufferType
    {
        Version = 0,
        Empty= 0,
        Data= 1,
        Token= 2
    }
}
