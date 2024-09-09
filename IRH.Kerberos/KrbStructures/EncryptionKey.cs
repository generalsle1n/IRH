using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace IRH.Kerberos
{
    public class EncryptionKey
    {

        public EncryptionKey()
        {
            keytype = 0;

            keyvalue = null;
        }

        public EncryptionKey(AsnElt body)
        {
            foreach (AsnElt s in body.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        keytype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        keyvalue = s.Sub[0].GetOctetString();
                        break;
                    case 2:
                        keyvalue = s.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            AsnElt keyTypeElt = AsnElt.MakeInteger(keytype);
            AsnElt keyTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { keyTypeElt });
            keyTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, keyTypeSeq);


            AsnElt blob = AsnElt.MakeBlob(keyvalue);
            AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { blob });
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, blobSeq);


            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { keyTypeSeq, blobSeq });
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });

            return seq2;
        }

        public Int32 keytype { get; set; }

        public byte[] keyvalue { get; set; }
    }
}