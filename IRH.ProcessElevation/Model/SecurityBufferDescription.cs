using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace IRH.ProcessElevation.Model
{
    internal class SecurityBufferDescription : IDisposable
    {
        internal int Version;
        internal int Buffer;
        internal IntPtr BufferPointer;

        internal SecurityBufferDescription(int BufferSize)
        {
            Version = (int)SecurityBufferType.Version;
            Buffer = 1;
            SecurityBuffer SecurityBuffer = new SecurityBuffer(BufferSize);
            BufferPointer = Marshal.AllocHGlobal(Marshal.SizeOf(SecurityBuffer));
            Marshal.StructureToPtr(SecurityBuffer, BufferPointer, false);
        }

        internal SecurityBufferDescription(byte[] SecurityBufferBytes)
        {
            Version = (int)SecurityBufferType.Version;
            Buffer = 1;
            SecurityBuffer SecurityBuffer = new SecurityBuffer(SecurityBufferBytes);
            BufferPointer = Marshal.AllocHGlobal(Marshal.SizeOf(SecurityBuffer));
            Marshal.StructureToPtr(SecurityBuffer, BufferPointer, false);
        }

        internal SecurityBufferDescription(MultipleSecurityBufferHelper[] SecBufferBytesArray)
        {
            if (SecBufferBytesArray == null || SecBufferBytesArray.Length == 0)
            {
                throw new ArgumentException("SecBufferBytesArray was zero or null");
            }

            Version = (int)SecurityBufferType.Version;
            Buffer = SecBufferBytesArray.Length;

            BufferPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityBuffer)) * Buffer);

            for (int Index = 0; Index < SecBufferBytesArray.Length; Index++)
            {
                SecurityBuffer SecurityBuffer = new SecurityBuffer(SecBufferBytesArray[Index].Buffer, SecBufferBytesArray[Index].BufferType);
                int Offset = Index * Marshal.SizeOf(typeof(SecurityBuffer));
                Marshal.WriteInt32(BufferPointer, Offset, SecurityBuffer.Buffer);
                Marshal.WriteInt32(BufferPointer, Offset + Marshal.SizeOf(SecurityBuffer.Buffer), SecurityBuffer.BufferType);
                Marshal.WriteIntPtr(BufferPointer, Offset + Marshal.SizeOf(SecurityBuffer.Buffer) + Marshal.SizeOf(SecurityBuffer.BufferType), SecurityBuffer.BufferPointer);
            }
        }

        public void Dispose()
        {
            if (BufferPointer != IntPtr.Zero)
            {
                if (Buffer == 1)
                {
                    SecurityBuffer SecurityBuffer = (SecurityBuffer)Marshal.PtrToStructure(BufferPointer, typeof(SecurityBuffer));
                    SecurityBuffer.Dispose();
                }
                else
                {
                    for (int ItemIndex = 0; ItemIndex < Buffer; ItemIndex++)
                    {
                        int CurrentOffset = ItemIndex * Marshal.SizeOf(typeof(SecurityBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(BufferPointer, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(BufferPointer);
                BufferPointer = IntPtr.Zero;
            }
        }
    }
}
