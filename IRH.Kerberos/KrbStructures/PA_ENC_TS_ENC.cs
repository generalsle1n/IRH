using Asn1;
using System;
using System.Text;

namespace IRH.Kerberos
{

    public class PA_ENC_TS_ENC
    {
        public PA_ENC_TS_ENC()
        {
            patimestamp = DateTime.UtcNow;
        }

        public PA_ENC_TS_ENC(DateTime time)
        {
            patimestamp = time;
        }



        public AsnElt Encode()
        {
            AsnElt patimestampAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, patimestamp.ToString("yyyyMMddHHmmssZ"));
            AsnElt patimestampSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { patimestampAsn });
            patimestampSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, patimestampSeq);

            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { patimestampSeq });

            return totalSeq;
        }

        public DateTime patimestamp { get; set; }

        public int pausec { get; set; }

    }
}