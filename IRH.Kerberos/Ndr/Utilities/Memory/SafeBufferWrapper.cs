using System;
using System.Runtime.InteropServices;

namespace IRH.Kerberos.Utilities.Memory
{
    internal class SafeBufferWrapper : SafeBuffer
    {
        public SafeBufferWrapper(IntPtr buffer)
            : base(false)
        {
            Initialize(int.MaxValue);
            handle = buffer;
        }

        protected override bool ReleaseHandle()
        {
            return true;
        }
    }
}
