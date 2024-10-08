﻿using Asn1;
using System;

namespace IRH.Kerberos {
    public class PA_PK_AS_REP {

        public KrbDHRepInfo DHRepInfo { get; private set; }

        public PA_PK_AS_REP(AsnElt asnElt) {

            if(asnElt.TagClass != AsnElt.CONTEXT || asnElt.Sub.Length > 1) {
                throw new ArgumentException("Expected CONTEXT with CHOICE for PA-PK-AS-REP");
            }

            switch (asnElt.TagValue) {
                case 0: 
                    DHRepInfo = new KrbDHRepInfo(asnElt.Sub[0]);
                    break;

                case 1:  
                    break;

                default:
                    throw new ArgumentException("Unexpected CHOICE value for PA-PK-AS-REP");
            }          
        }
    }
}
