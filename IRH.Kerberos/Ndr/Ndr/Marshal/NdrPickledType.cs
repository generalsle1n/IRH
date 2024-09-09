using System;
using System.IO;
using IRH.Kerberos.Win32.Rpc;

namespace IRH.Kerberos.Ndr.Marshal
{
    public class NdrPickledType
    {
        public NdrPickledType(byte[] encoded)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(encoded));
            if (reader.ReadByte() != 1)
            {
                throw new ArgumentException("Only support version 1 serialization");
            }
            if (reader.ReadByte() != 0x10)
            {
                throw new ArgumentException("Only support little-endian NDR data.");
            }
            if (reader.ReadInt16() != 8)
            {
                throw new ArgumentException("Unexpected header length");
            }
            reader.ReadInt32();
            int length = reader.ReadInt32();
            reader.ReadInt32();
            Data = reader.ReadAllBytes(length);
            DataRepresentation = new NdrDataRepresentation()
            {
                IntegerRepresentation = NdrIntegerRepresentation.LittleEndian,
                CharacterRepresentation = NdrCharacterRepresentation.ASCII,
                FloatingPointRepresentation = NdrFloatingPointRepresentation.IEEE
            };
        }

        internal NdrPickledType(byte[] data, NdrDataRepresentation data_representation)
        {
            DataRepresentation = data_representation;
            if (DataRepresentation.CharacterRepresentation != NdrCharacterRepresentation.ASCII ||
                DataRepresentation.FloatingPointRepresentation != NdrFloatingPointRepresentation.IEEE)
            {
                throw new ArgumentException("Invalid data representation for type 1 serialized buffer");
            }
            Data = data;
        }

        internal byte[] Data { get; }

        internal NdrDataRepresentation DataRepresentation { get; }

        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);

            writer.Write((byte)1);
            writer.Write((byte)(DataRepresentation.IntegerRepresentation == NdrIntegerRepresentation.LittleEndian ? 0x10 : 0));
            writer.Write((short)8);
            writer.Write(0xCCCCCCCCU);

            writer.Write(Data.Length);
            writer.Write(0);
            writer.Write(Data);
            return stm.ToArray();
        }
    }
}
