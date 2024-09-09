using Asn1;
using System;
using System.Text;

namespace IRH.Kerberos
{
    public class TGS_REP
    {
        public TGS_REP(byte[] data)
        {
            AsnElt asn_TGS_REP = AsnElt.Decode(data, false);

            this.Decode(asn_TGS_REP);
        }

        public TGS_REP(AsnElt asn_TGS_REP)
        {
            this.Decode(asn_TGS_REP);
        }

        private void Decode(AsnElt asn_TGS_REP)
        {
            if (asn_TGS_REP.TagValue != (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
            {
                throw new System.Exception("TGS-REP tag value should be 13");
            }

            if ((asn_TGS_REP.Sub.Length != 1) || (asn_TGS_REP.Sub[0].TagValue != 16))
            {
                throw new System.Exception("First TGS-REP sub should be a sequence");
            }

            AsnElt[] kdc_rep = asn_TGS_REP.Sub[0].Sub;

            foreach (AsnElt s in kdc_rep)
            {
                switch (s.TagValue)
                {
                    case 0:
                        pvno = s.Sub[0].GetInteger();
                        break;
                    case 1:
                        msg_type = s.Sub[0].GetInteger();
                        break;
                    case 2:
                        padata = new PA_DATA(s.Sub[0]);
                        break;
                    case 3:
                        crealm = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 4:
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 5:
                        ticket = new Ticket(s.Sub[0].Sub[0]);
                        break;
                    case 6:
                        enc_part = new EncryptedData(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public PA_DATA padata { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public Ticket ticket { get; set; }

        public EncryptedData enc_part { get; set; }
    }
}
