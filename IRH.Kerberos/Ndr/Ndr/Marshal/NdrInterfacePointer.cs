using IRH.Kerberos.Win32.Rpc;

namespace IRH.Kerberos.Ndr.Marshal
{
    public struct NdrInterfacePointer : INdrConformantStructure
    {
        public byte[] Data { get; set; }

        public NdrInterfacePointer(byte[] data)
        {
            Data = data;
        }

        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }

        void INdrStructure.Marshal(NdrMarshalBuffer marshal)
        {
            RpcUtils.CheckNull(Data, "Data");
            marshal.WriteInt32(Data.Length);
            marshal.WriteConformantByteArray(Data, Data.Length);
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer unmarshal)
        {
            unmarshal.ReadInt32();
            Data = unmarshal.ReadConformantByteArray();
        }

        int INdrStructure.GetAlignment()
        {
            return 4;
        }
    }
}
