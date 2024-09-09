using Asn1;
using System;
using System.Text;

namespace IRH.Kerberos
{
    class PA_KEY_LIST_REQ
    {
        public PA_KEY_LIST_REQ()
        {
            Enctype = (Int32)Interop.KERB_ETYPE.rc4_hmac;
        }

        public PA_KEY_LIST_REQ(Interop.KERB_ETYPE etype)
        {
            Enctype = (Int32)etype;
        }
        public AsnElt Encode()
        {
            AsnElt enctypeAsn = AsnElt.MakeInteger(Enctype);
            AsnElt enctypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { enctypeAsn });
            return enctypeSeq;
        }

        public Int32 Enctype { get; set; }

    }
}