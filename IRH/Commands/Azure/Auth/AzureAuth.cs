using Azure.Identity;
using Microsoft.Graph;
using BGraphServiceClient = Microsoft.Graph.Beta.GraphServiceClient;

namespace IRH.Commands.Azure.Auth
{
    internal class AzureAuth
    {
        internal GraphServiceClient GetClient(string AppIDValue, string TenantIDValue, string[] ScopesValue, AuthType Type)
        {
            GraphServiceClient Client = null;
            switch (Type)
            {
                case AuthType.DeviceCode:
                    DeviceCodeCredential DeviceCredentials = CreateDeviceCodeCredential(AppIDValue, TenantIDValue);
                    Client = new GraphServiceClient(DeviceCredentials, ScopesValue);
                    break;
                case AuthType.Interactive:
                    InteractiveBrowserCredential InteractiveCredentials = CreateInteractiveBrowserCredential(AppIDValue, TenantIDValue);
                    Client = new GraphServiceClient(InteractiveCredentials, ScopesValue);
                    break;
            }

            return Client;
        }
        internal BGraphServiceClient GetClientBeta(string AppIDValue, string TenantIDValue, string[] ScopesValue, AuthType Type)
        {
            BGraphServiceClient Client = null;

            switch (Type)
            {
                case AuthType.DeviceCode:
                    DeviceCodeCredential DeviceCredentials = CreateDeviceCodeCredential(AppIDValue, TenantIDValue);
                    Client = new BGraphServiceClient(DeviceCredentials, ScopesValue);
                    break;
                case AuthType.Interactive:
                    InteractiveBrowserCredential InteractiveCredentials = CreateInteractiveBrowserCredential(AppIDValue, TenantIDValue);
                    Client = new BGraphServiceClient(InteractiveCredentials, ScopesValue);
                    break;
            }

            return Client;
        }

        private DeviceCodeCredential CreateDeviceCodeCredential(string AppID, string TenantID)
        {
            DeviceCodeCredentialOptions Options = new DeviceCodeCredentialOptions
            {
                AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                ClientId = AppID,
                TenantId = TenantID,

                DeviceCodeCallback = (code, cancellation) =>
                {
                    Console.WriteLine(code.Message);
                    return Task.FromResult(0);
                },
            };

            return new DeviceCodeCredential(Options);
        }

        private InteractiveBrowserCredential CreateInteractiveBrowserCredential(string AppID, string TenantID)
        {
            InteractiveBrowserCredentialOptions Options = new InteractiveBrowserCredentialOptions
            {
                TenantId = TenantID,
                ClientId = AppID,
                AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                // MUST be http://localhost or http://localhost:PORT
                // See https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/System-Browser-on-.Net-Core
                RedirectUri = new Uri("http://localhost"),
            };

            // https://learn.microsoft.com/dotnet/api/azure.identity.interactivebrowsercredential
            return new InteractiveBrowserCredential(Options);
        }
    }
}
