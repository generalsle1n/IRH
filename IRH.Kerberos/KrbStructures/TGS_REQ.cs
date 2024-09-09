using Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace IRH.Kerberos
{


    public class TGS_REQ
    {
        public static byte[] NewTGSReq(string userName, string domain, string sname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, bool renew = false, string s4uUser = "", bool enterprise = false, bool roast = false, bool opsec = false, bool unconstrained = false, KRB_CRED tgs = null, string targetDomain = "", bool u2u = false, bool keyList = false)
        {
            TGS_REQ req;
            if (u2u)
                req = new TGS_REQ(!u2u);
            else
                req = new TGS_REQ(!opsec);

            if (!opsec && !u2u)
            {
                req.req_body.cname.name_string.Add(userName);
            }

            string[] parts = sname.Split('/');
            if (String.IsNullOrEmpty(targetDomain))
            {
                if (!(roast) && (parts.Length > 1) && (parts[0] != "krbtgt") && (tgs == null) && parts[0] != "kadmin")
                {
                    if (parts[1].Split('.').Length > 2)
                    {
                        targetDomain = parts[1].Substring(parts[1].IndexOf('.') + 1);

                        string[] targetParts = targetDomain.Split(':');
                        if (targetParts.Length > 1)
                        {
                            targetDomain = targetParts[0];
                        }
                    }
                    if (String.IsNullOrEmpty(targetDomain))
                        targetDomain = domain;
                }
                else if (enterprise)
                {
                    targetDomain = sname.Split('@')[1];
                }
                else
                {
                    targetDomain = domain;
                }
            }

            req.req_body.realm = targetDomain.ToUpperInvariant();

            if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
            {
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
            }
            else if ((opsec) && (parts.Length > 1) && (parts[0] != "krbtgt"))
            {
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);
            }
            else
            {
                req.req_body.etypes.Add(requestEType);
            }

            if (!String.IsNullOrEmpty(s4uUser))
            {
                if (u2u)
                {
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.ENCTKTINSKEY | Interop.KdcOptions.FORWARDABLE | Interop.KdcOptions.RENEWABLE | Interop.KdcOptions.RENEWABLEOK;
                    req.req_body.sname.name_string.Add(sname);
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_UNKNOWN;
                }
                else
                {
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;
                    req.req_body.sname.name_string.Add(userName);
                }

                if (!opsec)
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.ENCTKTINSKEY;

                if (opsec)
                    req.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);
            }
            else if (u2u)
            {
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.ENCTKTINSKEY | Interop.KdcOptions.FORWARDABLE | Interop.KdcOptions.RENEWABLE | Interop.KdcOptions.RENEWABLEOK;
                req.req_body.sname.name_string.Add(sname);
                req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;
            }
            else
            {
                if (enterprise)
                {
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
                    req.req_body.sname.name_string.Add(sname);
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
                }
                else if (parts.Length == 1)
                {
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                    req.req_body.sname.name_string.Add(sname);
                    req.req_body.sname.name_string.Add(domain);
                }
                else if (parts.Length == 2)
                {
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                    req.req_body.sname.name_string.Add(parts[0]);
                    req.req_body.sname.name_string.Add(parts[1]);
                }
                else if (parts.Length == 3)
                {
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_HST;
                    req.req_body.sname.name_string.Add(parts[0]);
                    req.req_body.sname.name_string.Add(parts[1]);
                    req.req_body.sname.name_string.Add(parts[2]);
                }
                else
                {
                    Console.WriteLine("[X] Error: invalid TGS_REQ sname '{0}'", sname);
                }
            }

            if (renew)
            {
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.RENEW;
            }

            if (tgs != null)
            {
                req.req_body.additional_tickets.Add(tgs.tickets[0]);
                if (!u2u)
                {
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CONSTRAINED_DELEGATION | Interop.KdcOptions.CANONICALIZE;
                    req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;
                }
            }

            if (keyList)
            {
                req.req_body.kdcOptions = Interop.KdcOptions.CANONICALIZE;
            }

            byte[] cksum_Bytes = null;

            if (opsec)
            {
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
                if (!unconstrained)
                    req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;
                if (unconstrained)
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.FORWARDED;

                string hostName = Dns.GetHostName().ToUpperInvariant();
                string targetHostName;
                if (parts.Length > 1)
                {
                    targetHostName = parts[1].Substring(0, parts[1].IndexOf('.')).ToUpperInvariant();
                }
                else
                {
                    targetHostName = hostName;
                }

                if ((hostName != targetHostName) && String.IsNullOrEmpty(s4uUser) && (!unconstrained))
                {
                    ADIfRelevant ifrelevant = new ADIfRelevant();
                    ADRestrictionEntry restrictions = new ADRestrictionEntry();
                    ADKerbLocal kerbLocal = new ADKerbLocal();
                    ifrelevant.ADData.Add(restrictions);
                    ifrelevant.ADData.Add(kerbLocal);
                    AsnElt authDataSeq = ifrelevant.Encode();
                    authDataSeq = AsnElt.Make(AsnElt.SEQUENCE, authDataSeq);
                    byte[] authorizationDataBytes = authDataSeq.Encode();
                    byte[] enc_authorization_data = Crypto.KerberosEncrypt(paEType, Interop.KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA, clientKey, authorizationDataBytes);
                    req.req_body.enc_authorization_data = new EncryptedData((Int32)paEType, enc_authorization_data);
                }

                if (!String.IsNullOrEmpty(s4uUser))
                {
                    DateTime till = DateTime.Now;
                    till = till.AddMinutes(15).ToUniversalTime();
                    req.req_body.till = till;
                }

                AsnElt req_Body_ASN = req.req_body.Encode();
                AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
                req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);
                byte[] req_Body_Bytes = req_Body_ASNSeq.CopyValue();
                Interop.KERB_CHECKSUM_ALGORITHM checkSumType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD5;
                cksum_Bytes = Crypto.KerberosChecksum(clientKey, req_Body_Bytes, checkSumType, Interop.KRB_KEY_USAGE_TGS_REQ_CHECKSUM);
            }

            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, paEType, opsec, cksum_Bytes);
            req.padata.Add(padata);

            if (keyList)
            {
                PA_DATA keyListPaData = new PA_DATA(Interop.KERB_ETYPE.rc4_hmac);
                req.padata.Add(keyListPaData);
            }

            if (opsec && (!String.IsNullOrEmpty(s4uUser)))
            {
                domain = domain.ToLowerInvariant();

                PA_DATA s4upadata = new PA_DATA(clientKey, s4uUser, domain, req.req_body.nonce, paEType);
                req.padata.Add(s4upadata);
            }

            if (!String.IsNullOrEmpty(s4uUser))
            {
                PA_DATA s4upadata = new PA_DATA(clientKey, s4uUser, domain);
                req.padata.Add(s4upadata);
            }
            else if (opsec)
            {
                PA_DATA padataoptions = new PA_DATA(false, true, false, false);
                req.padata.Add(padataoptions);
            }
            else if ((tgs != null) && !u2u)
            {
                PA_DATA pac_options = new PA_DATA(false, false, false, true);
                req.padata.Add(pac_options);
            }

            return req.Encode().Encode();
        }

        public static byte[] NewTGSReq(string userName, string domain, string targetDomain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Interop.KERB_ETYPE requestEType)
        {
            TGS_REQ req = new TGS_REQ(cname: false);

            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, paEType);
            req.padata.Add(padata);

            req.req_body.realm = domain;

            if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
            {
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
            }
            else
            {
                req.req_body.etypes.Add(requestEType);
            }

            PA_DATA padataoptions = new PA_DATA(false, true, false, false);
            req.padata.Add(padataoptions);

            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            req.req_body.sname.name_string.Add("krbtgt");
            req.req_body.sname.name_string.Add(targetDomain);

            req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.FORWARDABLE;
            req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK & ~Interop.KdcOptions.RENEW;

            return req.Encode().Encode();
        }

        public static byte[] NewTGSReq(string userName, string targetUser, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Interop.KERB_ETYPE requestEType, bool cross = true, string requestDomain = "")
        {
            TGS_REQ req = new TGS_REQ(cname: false);

            string domain = userName.Split('@')[1];
            string targetDomain = targetUser.Split('@')[1];

            PA_DATA padata = new PA_DATA(domain, userName.Split('@')[0], providedTicket, clientKey, paEType);
            req.padata.Add(padata);

            if (cross)
            {
                if (String.IsNullOrEmpty(requestDomain))
                    requestDomain = targetDomain;

                req.req_body.realm = requestDomain;
            }
            else
            {
                req.req_body.realm = domain;
            }

            if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
            {
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
            }
            else
            {
                req.req_body.etypes.Add(requestEType);
            }

            PA_DATA s4upadata = new PA_DATA(clientKey, targetUser, targetDomain);
            req.padata.Add(s4upadata);

            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
            req.req_body.sname.name_string.Add(userName);

            req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.FORWARDABLE;
            req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK & ~Interop.KdcOptions.RENEW;

            return req.Encode().Encode();
        }

        public static byte[] NewTGSReq(byte[] kirbi)
        {

            return null;
        }


        public TGS_REQ(bool cname = true)
        {
            pvno = 5;

            msg_type = (long)Interop.KERB_MESSAGE_TYPE.TGS_REQ;

            padata = new List<PA_DATA>();

            req_body = new KDCReqBody(c: cname);
        }

        public AsnElt Encode()
        {
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, pvnoSeq);


            AsnElt msg_type_ASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_type_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_type_ASN });
            msg_type_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, msg_type_ASNSeq);


            List<AsnElt> padatas = new List<AsnElt>();
            foreach (PA_DATA pa in padata)
            {
                padatas.Add(pa.Encode());
            }
            AsnElt padata_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, padatas.ToArray());
            AsnElt padata_ASNSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { padata_ASNSeq });
            padata_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, padata_ASNSeq2);


            AsnElt req_Body_ASN = req_body.Encode();
            AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
            req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);


            AsnElt[] total = new[] { pvnoSeq, msg_type_ASNSeq, padata_ASNSeq, req_Body_ASNSeq };
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, total);

            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 12, totalSeq);

            return totalSeq;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public List<PA_DATA> padata { get; set; }

        public KDCReqBody req_body { get; set; }
    }
}
