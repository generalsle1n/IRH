namespace IRH.Kerberos.Ndr.Marshal
{
    public interface INdrNonEncapsulatedUnion : INdrStructure
    {
        void Marshal(NdrMarshalBuffer marshal, long selector);
    }
}
