using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.General
{
    internal class ByteArrayHelper
    {
        private static readonly byte[] _seperator = new byte[] { 0xFF };

        internal static byte[] MergeArray(byte[] FirstArray, byte[] SecondArray)
        {
            List<byte> Result = new List<byte>();

            Result.AddRange(FirstArray);
            Result.AddRange(_seperator);
            Result.AddRange(SecondArray);

            return Result.ToArray();
        }
    }
}
