using Azure.Identity;
using Microsoft.Graph;
using BGraphServiceClient = Microsoft.Graph.Beta.GraphServiceClient;

namespace IRH.Commands.Azure.Auth
{
    internal class AzureAuth
    {
        internal GraphServiceClient GetDeviceClient(string AppIDValue, string TenantIDValue, string[] ScopesValue)
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
        internal BGraphServiceClient GetDeviceClientBeta(string AppIDValue, string TenantIDValue, string[] ScopesValue)
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
            BGraphServiceClient Client = new BGraphServiceClient(Credentials, ScopesValue);

            return Client;
        }

    }
}
