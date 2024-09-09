using System;
using System.IO;
using System.Runtime.InteropServices;

namespace IRH.Kerberos.Utilities.Memory
{
    internal interface IConvertToNative<T> where T : struct
    {
        T Convert();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IntPtr32 : IConvertToNative<IntPtr>
    {
        public int value;

        public IntPtr Convert()
        {
            return new IntPtr(value);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UIntPtr32 : IConvertToNative<UIntPtr>
    {
        public uint value;

        public UIntPtr Convert()
        {
            return new UIntPtr(value);
        }
    }

    internal interface IMemoryReader
    {
        byte ReadByte(IntPtr address);
        byte[] ReadBytes(IntPtr address, int length);
        short ReadInt16(IntPtr address);
        IntPtr ReadIntPtr(IntPtr address);
        int ReadInt32(IntPtr address);
        T ReadStruct<T>(IntPtr address) where T : struct;
        T[] ReadArray<T>(IntPtr address, int count) where T : struct;
        BinaryReader GetReader(IntPtr address);
        bool InProcess { get; }
        int PointerSize { get; }
        string ReadAnsiStringZ(IntPtr address);
    }
}
