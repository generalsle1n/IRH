using System;

namespace IRH.Kerberos.Ndr.Marshal
{
    public struct NdrInt3264 : IFormattable
    {
        public readonly int Value;

        public NdrInt3264(int value)
        {
            Value = value;
        }

        public NdrInt3264(IntPtr value)
        {
            Value = (int)value.ToInt64();
        }

        public static implicit operator IntPtr(NdrInt3264 i)
        {
            return new IntPtr(i.Value);
        }

        public override string ToString()
        {
            return Value.ToString();
        }

        public string ToString(string format)
        {
            return Value.ToString(format);
        }

        public string ToString(string format, IFormatProvider formatProvider)
        {
            return Value.ToString(format, formatProvider);
        }
    }

    public struct NdrUInt3264 : IFormattable
    {
        public readonly uint Value;

        public NdrUInt3264(uint value)
        {
            Value = value;
        }

        public NdrUInt3264(int value)
            : this((uint)value)
        {
        }

        public NdrUInt3264(IntPtr value)
        {
            Value = (uint)(value.ToInt64() & uint.MaxValue);
        }

        public static implicit operator IntPtr(NdrUInt3264 i)
        {
            if (IntPtr.Size == 8)
            {
                return new IntPtr(i.Value);
            }
            return new IntPtr((int)i.Value);
        }

        public override string ToString()
        {
            return Value.ToString();
        }

        public string ToString(string format)
        {
            return Value.ToString(format);
        }

        public string ToString(string format, IFormatProvider formatProvider)
        {
            return Value.ToString(format, formatProvider);
        }
    }
}
