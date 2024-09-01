using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal class SecurityBuffer : IDisposable
    {
        internal int Buffer;
        internal int BufferType;
        internal IntPtr BufferPointer;


        internal SecurityBuffer(int BufferSize)
        {
            Buffer = BufferSize;
            BufferType = (int)SecurityBufferType.Token;
            BufferPointer = Marshal.AllocHGlobal(BufferSize);
        }

        internal SecurityBuffer(byte[] SecurityBufferBytes)
        {
            Buffer = SecurityBufferBytes.Length;
            BufferType = (int)SecurityBufferType.Token;
            BufferPointer = Marshal.AllocHGlobal(BufferPointer);
            Marshal.Copy(SecurityBufferBytes, 0, BufferPointer, Buffer);
        }

        internal SecurityBuffer(byte[] SecurityBufferBytes, SecurityBufferType Type)
        {
            Buffer = SecurityBufferBytes.Length;
            BufferType = (int)Type;
            BufferPointer = Marshal.AllocHGlobal(Buffer);
            Marshal.Copy(SecurityBufferBytes, 0, BufferPointer, Buffer);
        }

        public void Dispose()
        {
            if (BufferPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(BufferPointer);
                BufferPointer = IntPtr.Zero;
            }
        }
    }
}
