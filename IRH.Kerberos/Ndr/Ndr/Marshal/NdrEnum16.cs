using System;

namespace IRH.Kerberos.Ndr.Marshal
{
    public struct NdrEnum16 : IFormattable, IEquatable<NdrEnum16>
    {
        public readonly int Value;

        public NdrEnum16(int value)
        {
            Value = value;
        }

        public static implicit operator NdrEnum16(int value)
        {
            return new NdrEnum16(value);
        }

        public static implicit operator int(NdrEnum16 value)
        {
            return value.Value;
        }

        public static explicit operator NdrEnum16(uint value)
        {
            return new NdrEnum16((int)value);
        }

        public static explicit operator long(NdrEnum16 value)
        {
            return value.Value;
        }

        public static explicit operator NdrEnum16(long value)
        {
            return new NdrEnum16((int)value);
        }

        public static explicit operator NdrEnum16(Enum value)
        {
            Type enum_type = value.GetType().GetEnumUnderlyingType();
            if (enum_type == typeof(uint))
            {
                return (NdrEnum16)Convert.ToUInt32(value);
            }
            return new NdrEnum16(Convert.ToInt32(value));
        }

        public static explicit operator uint(NdrEnum16 value)
        {
            return (uint)value.Value;
        }

        public static bool operator ==(NdrEnum16 left, NdrEnum16 right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(NdrEnum16 left, NdrEnum16 right)
        {
            return !left.Equals(right);
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

        public bool Equals(NdrEnum16 other)
        {
            return Value == other.Value;
        }

        public override bool Equals(object obj)
        {
            if (obj is NdrEnum16 e)
            {
                return Equals(e);
            }
            return false;
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }
    }
}
