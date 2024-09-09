using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;

namespace IRH.Kerberos
{
    public class ETYPE_INFO2_ENTRY
    {

        public ETYPE_INFO2_ENTRY(AsnElt body)
        {
            foreach (AsnElt s in body.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        etype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        salt = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    default:
                        break;
                }
            }
        }

        public Int32 etype { get; set; }

        public string salt { get; set; }

    }
}
