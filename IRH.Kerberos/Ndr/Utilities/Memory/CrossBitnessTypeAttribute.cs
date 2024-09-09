using System;
using System.Reflection;

namespace IRH.Kerberos.Utilities.Memory
{
    internal class CrossBitnessTypeAttribute : Attribute
    {
        public Type CrossBitnessType { get; }

        private static MethodInfo GetMethodInfo(Type cross_bitness_type)
        {
            return null;
        }

        public CrossBitnessTypeAttribute(Type cross_bitness_type)
        {

        }

        public int GetSize()
        {
            return System.Runtime.InteropServices.Marshal.SizeOf(CrossBitnessType);
        }
    }
}
