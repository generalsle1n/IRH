using System;

namespace IRH.Kerberos.Ndr.Marshal
{
    public struct NdrContextHandle
    {
        public int Attributes { get; }

        public Guid Uuid { get; }

        public NdrContextHandle(int attributes, Guid uuid)
        {
            Attributes = attributes;
            Uuid = uuid;
        }

        public override string ToString()
        {
            return $"Handle: {Uuid} - Attributes: {Attributes}";
        }
    }
}
