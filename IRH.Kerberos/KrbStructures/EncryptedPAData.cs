using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace IRH.Kerberos
{
    public class EncryptedPAData
    {
        public EncryptedPAData()
        {
            keytype = 0;

            keyvalue = null;
        }

        public EncryptedPAData(AsnElt body)
        {
            foreach (AsnElt s in body.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 1:
                        keytype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        keyvalue = s.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }

            if (keytype == (Int32)Interop.PADATA_TYPE.KEY_LIST_REP)
            {
                AsnElt ae = AsnElt.Decode(keyvalue);
                PA_KEY_LIST_REP = new PA_KEY_LIST_REP(ae);
            }

        }

        public Int32 keytype { get; set; }

        public byte[] keyvalue { get; set; }

        public PA_KEY_LIST_REP PA_KEY_LIST_REP { get; set; }
    }
}