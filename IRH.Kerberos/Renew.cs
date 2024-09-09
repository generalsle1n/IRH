using System;
using System.IO;
using System.Linq;
using Asn1;
using IRH.Kerberos.lib.Interop;


namespace IRH.Kerberos
{
    public class Renew
    {
        public static void TGTAutoRenew(KRB_CRED kirbi, string domainController = "", bool display = true)
        {
            KRB_CRED currentKirbi = kirbi;

            while (true)
            {
                string userName = currentKirbi.enc_part.ticket_info[0].pname.name_string[0];
                string domain = currentKirbi.enc_part.ticket_info[0].prealm;
                Console.WriteLine("\r\n\r\n[*] User       : {0}@{1}", userName, domain);

                DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(currentKirbi.enc_part.ticket_info[0].endtime);
                DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(currentKirbi.enc_part.ticket_info[0].renew_till);
                Console.WriteLine("[*] endtime    : {0}", endTime);
                Console.WriteLine("[*] renew-till : {0}", renewTill);

                if (endTime > renewTill)
                {
                    Console.WriteLine("\r\n[*] renew-till window ({0}) has passed.\r\n", renewTill);
                    return;
                }
                else
                {
                    double ticks = (endTime - DateTime.Now).Ticks;
                    if (ticks < 0)
                    {
                        Console.WriteLine("\r\n[*] endtime is ({0}) has passed, no renewal possible.\r\n", endTime);
                        return;
                    }

                    double sleepMinutes = TimeSpan.FromTicks((endTime - DateTime.Now).Ticks).TotalMinutes - 30;

                    Console.WriteLine("[*] Sleeping for {0} minutes (endTime-30) before the next renewal", (int)sleepMinutes);
                    System.Threading.Thread.Sleep((int)sleepMinutes * 60 * 1000);

                    Console.WriteLine("[*] Renewing TGT for {0}@{1}\r\n", userName, domain);
                    byte[] bytes = TGT(currentKirbi, null, false, domainController, true);
                    currentKirbi = new KRB_CRED(bytes);
                }
            }
        }

        public static byte[] TGT(KRB_CRED kirbi, string outfile = "", bool ptt = false, string domainController = "", bool display = true)
        {
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            return TGT(userName, domain, ticket, clientKey, etype, outfile, ptt, domainController, display);
        }

        public static byte[] TGT(string userName, string domain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", bool display = true)
        {
            string dcIP = Networking.GetDCIP(domainController, display, domain);
            if (String.IsNullOrEmpty(dcIP)) { return null; }

            if (display)
            {
                Console.WriteLine("[*] Building TGS-REQ renewal for: '{0}\\{1}'", domain, userName);
            }

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, "krbtgt", providedTicket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, true, "");

            byte[] response = Networking.SendBytes(dcIP.ToString(), 88, tgsBytes);
            if (response == null)
            {
                return null;
            }

            AsnElt responseAsn = AsnElt.Decode(response, false);

            int responseTag = responseAsn.TagValue;

            if (responseTag == 13)
            {
                Console.WriteLine("[+] TGT renewal request successful!");

                TGS_REP rep = new TGS_REP(responseAsn);

                byte[] outBytes = Crypto.KerberosDecrypt(etype, 8, clientKey, rep.enc_part.cipher);
                AsnElt ae = AsnElt.Decode(outBytes, false);
                EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);

                KRB_CRED cred = new KRB_CRED();

                cred.tickets.Add(rep.ticket);

                KrbCredInfo info = new KrbCredInfo();

                info.key.keytype = encRepPart.key.keytype;
                info.key.keyvalue = encRepPart.key.keyvalue;

                info.prealm = encRepPart.realm;

                info.pname.name_type = rep.cname.name_type;
                info.pname.name_string = rep.cname.name_string;

                info.flags = encRepPart.flags;

                info.starttime = encRepPart.starttime;

                info.endtime = encRepPart.endtime;

                info.renew_till = encRepPart.renew_till;

                info.srealm = encRepPart.realm;

                info.sname.name_type = encRepPart.sname.name_type;
                info.sname.name_string = encRepPart.sname.name_string;

                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();

                string kirbiString = Convert.ToBase64String(kirbiBytes);

                if (display)
                {
                    Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);
                    if (Program.wrapTickets)
                    {
                        foreach (string line in Helpers.Split(kirbiString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("      {0}", kirbiString);
                    }
                }

                if (!String.IsNullOrEmpty(outfile))
                {
                    outfile = Helpers.MakeValidFileName(outfile);
                    if (Helpers.WriteBytesToFile(outfile, kirbiBytes))
                    {
                        if (display)
                        {
                            Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", outfile);
                        }
                    }
                }

                if (ptt)
                {
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }
                return kirbiBytes;
            }
            else if (responseTag == 30)
            {
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            else
            {
                Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
            }
            return null;
        }
    }
}