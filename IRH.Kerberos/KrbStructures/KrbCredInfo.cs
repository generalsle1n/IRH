using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace IRH.Kerberos
{
    public class KrbCredInfo
    {

        public KrbCredInfo()
        {
            key = new EncryptionKey();

            prealm = "";

            pname = new PrincipalName();

            flags = 0;

            srealm = "";

            sname = new PrincipalName();
        }

        public KrbCredInfo(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        key = new EncryptionKey(s);
                        break;
                    case 1:
                        prealm = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 2:
                        pname = new PrincipalName(s.Sub[0]);
                        break;
                    case 3:
                        UInt64 temp = Convert.ToUInt64(s.Sub[0].GetInteger());
                        byte[] tempBytes = BitConverter.GetBytes(temp);
                        flags = (Interop.TicketFlags)BitConverter.ToInt32(tempBytes, 0);
                        break;
                    case 4:
                        authtime = s.Sub[0].GetTime();
                        break;
                    case 5:
                        starttime = s.Sub[0].GetTime();
                        break;
                    case 6:
                        endtime = s.Sub[0].GetTime();
                        break;
                    case 7:
                        renew_till = s.Sub[0].GetTime();
                        break;
                    case 8:
                        srealm = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 9:
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            List<AsnElt> asnElements = new List<AsnElt>();

            AsnElt keyAsn = key.Encode();
            keyAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, keyAsn);
            asnElements.Add(keyAsn);


            if (!String.IsNullOrEmpty(prealm))
            {
                AsnElt prealmAsn = AsnElt.MakeString(AsnElt.UTF8String, prealm);
                prealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, prealmAsn);
                AsnElt prealmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, prealmAsn);
                prealmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, prealmAsnSeq);

                asnElements.Add(prealmAsnSeq);
            }


            if ((pname.name_string != null) && (pname.name_string.Count != 0) && (!String.IsNullOrEmpty(pname.name_string[0])))
            {
                AsnElt pnameAsn = pname.Encode();
                pnameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, pnameAsn);
                asnElements.Add(pnameAsn);
            }


            byte[] flagBytes = BitConverter.GetBytes((UInt32)flags);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(flagBytes);
            }
            AsnElt flagBytesAsn = AsnElt.MakeBitString(flagBytes);
            AsnElt flagBytesSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { flagBytesAsn });
            flagBytesSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, flagBytesSeq);
            asnElements.Add(flagBytesSeq);


            if ((authtime != null) && (authtime != DateTime.MinValue))
            {
                AsnElt authtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, authtime.ToString("yyyyMMddHHmmssZ"));
                AsnElt authtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { authtimeAsn });
                authtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, authtimeSeq);
                asnElements.Add(authtimeSeq);
            }


            if ((starttime != null) && (starttime != DateTime.MinValue))
            {
                AsnElt starttimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, starttime.ToString("yyyyMMddHHmmssZ"));
                AsnElt starttimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { starttimeAsn });
                starttimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, starttimeSeq);
                asnElements.Add(starttimeSeq);
            }


            if ((endtime != null) && (endtime != DateTime.MinValue))
            {
                AsnElt endtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, endtime.ToString("yyyyMMddHHmmssZ"));
                AsnElt endtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { endtimeAsn });
                endtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, endtimeSeq);
                asnElements.Add(endtimeSeq);
            }


            if ((renew_till != null) && (renew_till != DateTime.MinValue))
            {
                AsnElt renew_tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, renew_till.ToString("yyyyMMddHHmmssZ"));
                AsnElt renew_tillSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { renew_tillAsn });
                renew_tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, renew_tillSeq);
                asnElements.Add(renew_tillSeq);
            }


            if (!String.IsNullOrEmpty(srealm))
            {
                AsnElt srealmAsn = AsnElt.MakeString(AsnElt.UTF8String, srealm);
                srealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, srealmAsn);
                AsnElt srealmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, srealmAsn);
                srealmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, srealmAsnSeq);
                asnElements.Add(srealmAsnSeq);
            }


            if ((sname.name_string != null) && (sname.name_string.Count != 0) && (!String.IsNullOrEmpty(sname.name_string[0])))
            {
                AsnElt pnameAsn = sname.Encode();
                pnameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, pnameAsn);
                asnElements.Add(pnameAsn);
            }




            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, asnElements.ToArray());

            return seq;
        }

        public EncryptionKey key { get; set; }

        public string prealm { get; set; }

        public PrincipalName pname { get; set; }

        public Interop.TicketFlags flags { get; set; }

        public DateTime authtime { get; set; }

        public DateTime starttime { get; set; }

        public DateTime endtime { get; set; }

        public DateTime renew_till { get; set; }

        public string srealm { get; set; }

        public PrincipalName sname { get; set; }

    }
}
