using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace IRH.Kerberos
{
    public class Authenticator
    {
        public Authenticator()
        {
            authenticator_vno = 5;

            crealm = "";

            cksum = null;

            cname = new PrincipalName();

            cusec = 0;

            ctime = DateTime.UtcNow;

            subkey = null;

            seq_number = 0;
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();


            AsnElt pvnoAsn = AsnElt.MakeInteger(authenticator_vno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);
            allNodes.Add(pvnoSeq);


            AsnElt realmAsn = AsnElt.MakeString(AsnElt.UTF8String, crealm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, realmSeq);
            allNodes.Add(realmSeq);


            AsnElt snameElt = cname.Encode();
            snameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, snameElt);
            allNodes.Add(snameElt);

            if (cksum != null)
            {
                AsnElt checksumAsn = cksum.Encode();
                checksumAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, checksumAsn);
                allNodes.Add(checksumAsn);
            }


            AsnElt nonceAsn = AsnElt.MakeInteger(cusec);
            AsnElt nonceSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { nonceAsn });
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, nonceSeq);
            allNodes.Add(nonceSeq);


            AsnElt tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, ctime.ToString("yyyyMMddHHmmssZ"));
            AsnElt tillSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { tillAsn });
            tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, tillSeq);
            allNodes.Add(tillSeq);

            if (subkey != null)
            {
                AsnElt keyAsn = subkey.Encode();
                keyAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, keyAsn);
                allNodes.Add(keyAsn);
            }

            if (seq_number != 0)
            {
                AsnElt seq_numberASN = AsnElt.MakeInteger(seq_number);
                AsnElt seq_numberSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq_numberASN });
                seq_numberSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, seq_numberSeq);
                allNodes.Add(seq_numberSeq);
            }

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());


            AsnElt final = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { seq });
            final = AsnElt.MakeImplicit(AsnElt.APPLICATION, 2, final);

            return final;
        }


        public long authenticator_vno { get; set; }

        public string crealm { get; set; }

        public Checksum cksum { get; set; }

        public PrincipalName cname { get; set; }

        public long cusec { get; set; }

        public DateTime ctime { get; set; }

        public EncryptionKey subkey { get; set; }

        public UInt32 seq_number { get; set; }
    }
}