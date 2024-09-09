using Asn1;
using System;
using System.Collections.Generic;
using System.IO;

namespace IRH.Kerberos
{

    public class AP_REQ
    {
        public AP_REQ(string crealm, string cname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype, int keyUsageSpec = Interop.KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR)
        {
            pvno = 5;

            msg_type = (long)Interop.KERB_MESSAGE_TYPE.AP_REQ;

            ap_options = 0;

            ticket = providedTicket;

            keyUsage = keyUsageSpec;

            enctype = etype;
            key = clientKey;

            authenticator = new Authenticator();
            authenticator.crealm = crealm;
            authenticator.cname = new PrincipalName(cname);
        }

        public AsnElt Encode()
        {
            AsnElt pvnoASN = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoASN });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);


            AsnElt msg_typeASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_typeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_typeASN });
            msg_typeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, msg_typeSeq);


            byte[] ap_optionsBytes = BitConverter.GetBytes(ap_options);
            AsnElt ap_optionsASN = AsnElt.MakeBitString(ap_optionsBytes);
            AsnElt ap_optionsSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { ap_optionsASN });
            ap_optionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, ap_optionsSeq);


            AsnElt ticketASN = ticket.Encode();
            AsnElt ticktSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { ticketASN });
            ticktSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, ticktSeq);


            if (key == null)
            {
                Console.WriteLine("  [X] A key for the authenticator is needed to build an AP-REQ");
                return null;
            }

            byte[] authenticatorBytes = authenticator.Encode().Encode();

            byte[] encBytes = Crypto.KerberosEncrypt(enctype, keyUsage, key, authenticatorBytes);

            EncryptedData authenticatorEncryptedData = new EncryptedData();
            authenticatorEncryptedData.etype = (int)enctype;
            authenticatorEncryptedData.cipher = encBytes;

            AsnElt authenticatorEncryptedDataASN = authenticatorEncryptedData.Encode();
            AsnElt authenticatorEncryptedDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { authenticatorEncryptedDataASN });
            authenticatorEncryptedDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, authenticatorEncryptedDataSeq);

            AsnElt[] total = new[] { pvnoSeq, msg_typeSeq, ap_optionsSeq, ticktSeq, authenticatorEncryptedDataSeq };
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, total);

            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 14, totalSeq);

            return totalSeq;
        }


        public long pvno { get; set; }

        public long msg_type { get; set; }

        public UInt32 ap_options { get; set; }

        public Ticket ticket { get; set; }

        public Authenticator authenticator { get; set; }

        public byte[] key { get; set; }

        private Interop.KERB_ETYPE enctype;

        private int keyUsage;
    }
}