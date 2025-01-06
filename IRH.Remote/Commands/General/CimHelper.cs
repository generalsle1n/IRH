using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using System;
using System.Collections.Generic;
using System.CommandLine.Parsing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Remote.Commands.General
{
    internal class CimHelper
    {
        internal static CimSession CreateSession(string RemoteMachine, string Domain, string Username, string Password, int TimeOut)
        {
            NetworkCredential RawCredential = new NetworkCredential(
                            Username,
                            Password,
                            Domain
                            );

            CimCredential Credential = new CimCredential(
                PasswordAuthenticationMechanism.Default,
                RawCredential.Domain,
                RawCredential.UserName,
                RawCredential.SecurePassword
                );

            DComSessionOptions Options = new DComSessionOptions()
            {
                Impersonation = ImpersonationType.Impersonate,
                Timeout = TimeSpan.FromSeconds(TimeOut)
            };
            Options.AddDestinationCredentials(Credential);

            CimSession Session = CimSession.Create(RemoteMachine, Options);
            return Session;
        }
    }
}
