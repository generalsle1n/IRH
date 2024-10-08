﻿using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace IRH.Kerberos
{
    public class LastReq
    {
        public LastReq(AsnElt body)
        {
            foreach (AsnElt s in body.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        lr_type = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        lr_value = s.Sub[0].GetTime();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            return null;
        }

        public Int32 lr_type { get; set; }

        public DateTime lr_value { get; set; }
    }
}