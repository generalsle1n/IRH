using Azure.Identity;
using Microsoft.Graph;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.Azure
{
    internal class AzureAuth
    {
        internal GraphServiceClient GetClient(string AppIDValue, string TenantIDValue, string[] ScopesValue)
        {
            DeviceCodeCredentialOptions Options = new DeviceCodeCredentialOptions
            {
                AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                ClientId = AppIDValue,
                TenantId = TenantIDValue,

                DeviceCodeCallback = (code, cancellation) =>
                {
                    Console.WriteLine(code.Message);
                    return Task.FromResult(0);
                },
            };

            DeviceCodeCredential Credentials = new DeviceCodeCredential(Options);
            GraphServiceClient Client = new GraphServiceClient(Credentials, ScopesValue);

            return Client;
        }
    }
}
