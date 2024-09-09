using System;
using Asn1;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace IRH.Kerberos
{



    public class EncKrbPrivPart
    {
        public EncKrbPrivPart() : this("", "") { }

        public EncKrbPrivPart(string newPassword, string hostName) : this(null, null, newPassword, hostName) { }

        public EncKrbPrivPart(string username, string realm, string newPassword, string hostName)
        {

            this.username = username;
            this.realm = realm;
            new_password = newPassword;

            var rand = new Random();
            seq_number = (UInt32)rand.Next(1, Int32.MaxValue);

            host_name = hostName;
        }

        public AsnElt Encode()
        {
            byte[] pwBytes = Encoding.ASCII.GetBytes(new_password);
            AsnElt new_passwordAsn = AsnElt.MakeBlob(pwBytes);

            AsnElt new_passwordSeq;
            if (username == null)
                new_passwordSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                     AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, new_passwordAsn),
                });
            else
            {

                PrincipalName principal = new PrincipalName(username);

                new_passwordSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, new_passwordAsn),
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, principal.Encode()),
                    AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeString(AsnElt.GeneralString, realm)),
                });
            }

            new_passwordSeq = AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBlob(new_passwordSeq.Encode()));

            AsnElt seq_numberAsn = AsnElt.MakeInteger(seq_number);
            AsnElt seq_numberSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { seq_numberAsn });
            seq_numberSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, seq_numberSeq);

            AsnElt hostAddressTypeAsn = AsnElt.MakeInteger(20);
            AsnElt hostAddressTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { hostAddressTypeAsn });
            hostAddressTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, hostAddressTypeSeq);

            byte[] hostAddressAddressBytes = Encoding.UTF8.GetBytes(host_name);
            AsnElt hostAddressAddressAsn = AsnElt.MakeBlob(hostAddressAddressBytes);
            AsnElt hostAddressAddressSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { hostAddressAddressAsn });
            hostAddressAddressSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, hostAddressAddressSeq);

            AsnElt hostAddressSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { hostAddressTypeSeq, hostAddressAddressSeq });
            AsnElt hostAddressSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { hostAddressSeq });
            hostAddressSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, hostAddressSeq2);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { new_passwordSeq, seq_numberSeq, hostAddressSeq2 });
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });

            seq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 28, seq2);

            return seq2;
        }

        public string new_password { get; set; }

        public UInt32 seq_number { get; set; }

        public string host_name { get; set; }

        public string username { get; set; }

        public string realm { get; set; }
    }
}