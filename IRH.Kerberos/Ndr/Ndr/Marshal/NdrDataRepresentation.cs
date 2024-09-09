namespace IRH.Kerberos.Ndr.Marshal
{
#pragma warning disable 1591
    public enum NdrIntegerRepresentation
    {
        LittleEndian,
        BigEndian
    }

    public enum NdrCharacterRepresentation
    {
        ASCII,
        EBCDIC
    }

    public enum NdrFloatingPointRepresentation
    {
        IEEE,
        VAX,
        Cray,
        IBM
    }

    public struct NdrDataRepresentation
    {
        public NdrIntegerRepresentation IntegerRepresentation { get; set; }
        public NdrCharacterRepresentation CharacterRepresentation { get; set; }
        public NdrFloatingPointRepresentation FloatingPointRepresentation { get; set; }
    }
#pragma warning restore 1591
}
