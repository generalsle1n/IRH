namespace IRH.Kerberos.Ndr.Marshal
{
    public interface INdrStructure
    {
        void Marshal(NdrMarshalBuffer marshal);
        void Unmarshal(NdrUnmarshalBuffer unmarshal);
        int GetAlignment();
    }
}
