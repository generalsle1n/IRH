using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal class MultipleSecurityBufferHelper
    {
        internal byte[] Buffer;
        internal SecurityBufferType BufferType;

        internal MultipleSecurityBufferHelper(byte[] Buffer, SecurityBufferType BufferType)
        {
            if (Buffer == null || Buffer.Length == 0)
            {
                throw new ArgumentException("Buffer was zero or null");
            }

            Buffer = Buffer;
            BufferType = BufferType;
        }
    }
}
