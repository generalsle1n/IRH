using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace IRH.Kerberos
{
    public class PA_FOR_USER
    {
        public PA_FOR_USER(byte[] key, string name, string realm)
        {
            userName = new PrincipalName(name);
            userName.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
            userRealm = realm;

            auth_package = "Kerberos";

            byte[] nameTypeBytes = new byte[4];
            nameTypeBytes[0] = 0xa;

            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] realmBytes = Encoding.UTF8.GetBytes(userRealm);
            byte[] authPackageBytes = Encoding.UTF8.GetBytes(auth_package);

            byte[] finalBytes = new byte[nameTypeBytes.Length + nameBytes.Length + realmBytes.Length + authPackageBytes.Length];

            Array.Copy(nameTypeBytes, 0, finalBytes, 0, nameTypeBytes.Length);
            Array.Copy(nameBytes, 0, finalBytes, nameTypeBytes.Length, nameBytes.Length);
            Array.Copy(realmBytes, 0, finalBytes, nameTypeBytes.Length + nameBytes.Length, realmBytes.Length);
            Array.Copy(authPackageBytes, 0, finalBytes, nameTypeBytes.Length + nameBytes.Length + realmBytes.Length, authPackageBytes.Length);

            byte[] outBytes = Crypto.KerberosChecksum(key, finalBytes);

            Checksum checksum = new Checksum(outBytes);

            cksum = checksum;
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            AsnElt userNameAsn = userName.Encode();
            userNameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, userNameAsn);
            allNodes.Add(userNameAsn);

            AsnElt userRealmAsn = AsnElt.MakeString(AsnElt.UTF8String, userRealm);
            userRealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, userRealmAsn);
            AsnElt userRealmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { userRealmAsn });
            userRealmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, userRealmSeq);
            allNodes.Add(userRealmSeq);

            AsnElt checksumAsn = cksum.Encode();
            checksumAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, checksumAsn);
            allNodes.Add(checksumAsn);

            AsnElt auth_packageAsn = AsnElt.MakeString(AsnElt.IA5String, auth_package);
            auth_packageAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, auth_packageAsn);
            AsnElt auth_packageSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { auth_packageAsn });
            auth_packageSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, auth_packageSeq);
            allNodes.Add(auth_packageSeq);


            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());


            return seq;
        }

        public PrincipalName userName { get; set; }

        public string userRealm { get; set; }

        public Checksum cksum { get; set; }

        public string auth_package { get; set; }
    }
}