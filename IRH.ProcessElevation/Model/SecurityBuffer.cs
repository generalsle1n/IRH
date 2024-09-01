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
        public int Buffer;
        public int BufferType;
        public IntPtr BufferPointer;


        public SecurityBuffer(int BufferSize)
        {
            Buffer = BufferSize;
            BufferType = (int)SecurityBufferType.Token;
            BufferPointer = Marshal.AllocHGlobal(BufferSize);
        }

        public SecurityBuffer(byte[] SecurityBufferBytes)
        {
            Buffer = SecurityBufferBytes.Length;
            BufferType = (int)SecurityBufferType.Token;
            BufferPointer = Marshal.AllocHGlobal(BufferPointer);
            Marshal.Copy(SecurityBufferBytes, 0, BufferPointer, Buffer);
        }

        public SecurityBuffer(byte[] SecurityBufferBytes, SecurityBufferType Type)
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
