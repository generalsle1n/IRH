using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace IRH.Kerberos
{
    public class S4UUserID
    {
        public S4UUserID(string name, string realm, uint n)
        {
            nonce = n;

            cname = new PrincipalName(name);
            cname.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;

            crealm = realm;

            options = Interop.PA_S4U_X509_USER_OPTIONS.SIGN_REPLY;
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            AsnElt nonceAsn = AsnElt.MakeInteger(nonce);
            AsnElt nonceSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { nonceAsn });
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, nonceSeq);
            allNodes.Add(nonceSeq);

            AsnElt cnameElt = cname.Encode();
            cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, cnameElt);
            allNodes.Add(cnameElt);

            AsnElt realmAsn = AsnElt.MakeString(AsnElt.UTF8String, crealm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);

            byte[] optionsBytes = BitConverter.GetBytes((uint)options);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(optionsBytes);
            }
            AsnElt optionsAsn = AsnElt.MakeBitString(optionsBytes);
            AsnElt optionsSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { optionsAsn });
            optionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, optionsSeq);
            allNodes.Add(optionsSeq);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());
            return seq;
        }

        public UInt32 nonce { get; set; }

        public PrincipalName cname { get; set; }

        public string crealm { get; set; }

        public Interop.PA_S4U_X509_USER_OPTIONS options { get; set; }
    }
}
