using Azure.Identity;
using IRH.Lib.Model.Azure.Auth;
using Microsoft.Graph;
using Serilog;
using Azure.Core;
using Microsoft.Graph.Applications.Item.AddPassword;
using Microsoft.Graph.Models;
using BGraphServiceClient = Microsoft.Graph.Beta.GraphServiceClient;

namespace IRH.Lib.Class.Azure.Auth
{
    public class AzureAuth
    {
        public AzureAuth(ILogger logger)
        {
            _logger = logger;
        }

        private readonly ILogger _logger;

        public GraphServiceClient GetClient(string AppIDValue, string TenantIDValue, string[] ScopesValue, AuthType Type, DeviceCodeCredential CodeCredential = null)
        {
            GraphServiceClient Client = null;
            switch (Type)
            {
                case AuthType.DeviceCode:
                    if(CodeCredential is null)
                    {
                        _logger.Verbose("Create Client with DeviceCode authentication");
                        DeviceCodeCredentialOptions Options = CreateDeviceCodeCredentialOptions(AppIDValue, TenantIDValue);
                        DeviceCodeCredential DeviceCredentials = CreateDeviceCodeCredential(Options);
                        Client = new GraphServiceClient(DeviceCredentials, ScopesValue);
                    }
                    else
                    {
                        Client = new GraphServiceClient(CodeCredential, ScopesValue);
                    }
                    break;
                case AuthType.Interactive:
                    _logger.Verbose("Create Client with Interactive authentication");
                    InteractiveBrowserCredential InteractiveCredentials = CreateInteractiveBrowserCredential(AppIDValue, TenantIDValue);
                    Client = new GraphServiceClient(InteractiveCredentials, ScopesValue);
                    break;
            }

            return Client;
        }

        public BGraphServiceClient GetClientBeta(string AppIDValue, string TenantIDValue, string[] ScopesValue, AuthType Type, DeviceCodeCredential CodeCredential = null)
        {
            BGraphServiceClient Client = null;

            switch (Type)
            {
                case AuthType.DeviceCode:
                    if(CodeCredential is null)
                    {
                        _logger.Verbose("Create Beta Client with DeviceCode authentication");
                        DeviceCodeCredentialOptions Options = CreateDeviceCodeCredentialOptions(AppIDValue, TenantIDValue);
                        DeviceCodeCredential DeviceCredentials = CreateDeviceCodeCredential(Options);
                        Client = new BGraphServiceClient(DeviceCredentials, ScopesValue);
                    }
                    else
                    {
                        Client = new BGraphServiceClient(CodeCredential, ScopesValue);
                    }
                    break;
                case AuthType.Interactive:
                    _logger.Verbose("Create Beta Client with Interactive authentication");
                    InteractiveBrowserCredential InteractiveCredentials = CreateInteractiveBrowserCredential(AppIDValue, TenantIDValue);
                    Client = new BGraphServiceClient(InteractiveCredentials, ScopesValue);
                    break;
            }
            return Client;
        }

        public DeviceCodeCredential CreateDeviceCodeCredential(DeviceCodeCredentialOptions Options)
        {
            _logger.Verbose($"Create DeviceCodeCredential with AppID: {Options.ClientId} and TenantID: {Options.TenantId}");
            return new DeviceCodeCredential(Options);
        }

        public DeviceCodeCredentialOptions CreateDeviceCodeCredentialOptions(string AppID, string TenantID, bool CreateCallBack = true)
        {
            DeviceCodeCredentialOptions Options = new DeviceCodeCredentialOptions
            {
                AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                ClientId = AppID,
                TenantId = TenantID,
            };

            if(CreateCallBack)
            {
                Options.DeviceCodeCallback = (code, cancellation) =>
                {
                    Console.WriteLine(code.Message);
                    return Task.FromResult(0);
                };
            }

            return Options;
        }

        private InteractiveBrowserCredential CreateInteractiveBrowserCredential(string AppID, string TenantID)
        {
            _logger.Verbose($"Create InteractiveBrowserCredentialOptions with AppID: {AppID} and TenantID: {TenantID}");
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
        private ClientSecretCredential CreateClientSecretCredential(ApplicationLogin AppLogin)
        {
            ClientSecretCredentialOptions Options = new ClientSecretCredentialOptions
            {
                AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
            };

            // https://learn.microsoft.com/dotnet/api/azure.identity.clientsecretcredential
            ClientSecretCredential ClientSecretCredential = new ClientSecretCredential(AppLogin.TenantId, AppLogin.Id, AppLogin.Credential.SecretText, Options);
            
            return ClientSecretCredential;
        }
        public async Task<ApplicationLogin> CreateAppRegistrationAsync(GraphServiceClient Client, string[] Permissions)
        {
            ApplicationLogin Result = new ApplicationLogin();
            Application OperatorApp = await GetOperatorApplicationAsync(Client);
            
            if (OperatorApp is null)
            {
                _logger.Information("Operator Not Found so its need to be created");

                OperatorApp = new Application()
                {
                    DisplayName = DefaultValue.OperatorDisplayName,
                };

                OperatorApp = await Client.Applications.PostAsync(OperatorApp);
                
                _logger.Information($"Operator Created with Name: {OperatorApp.DisplayName} and  Id: {OperatorApp.AppId}");
            }

            ServicePrincipal Principal = await AssignApplicationPermissionAsync(Client, OperatorApp, Permissions);
            
            PasswordCredential Credential = await CreateApplicationSecretAsync(Client, OperatorApp, Principal);
            
            Result.Id = OperatorApp.AppId;
            Result.Credential = Credential;
            Result.RawApplication = OperatorApp;
            Result.TenantId = await GetTenantIdAsync(Client);
            
            return Result;
        }
        private async Task<Application> GetOperatorApplicationAsync(GraphServiceClient Client)
        {
            Application Result = null;

            ApplicationCollectionResponse AppCollection = await Client.Applications.GetAsync(filter =>
            {
                filter.QueryParameters.Filter = $"DisplayName eq '{DefaultValue.OperatorDisplayName}'";
            });

            if (AppCollection.Value.Count == 1)
            {
                Result = AppCollection.Value.First();
            }

            return Result;
        }
        private async Task<PasswordCredential> CreateApplicationSecretAsync(GraphServiceClient Client, Application OperatorApp, ServicePrincipal ServicePrincipal)
        {
            AddPasswordPostRequestBody AddPassword = new AddPasswordPostRequestBody
            {
                PasswordCredential = new PasswordCredential
                {
                    DisplayName = DateTime.Now.ToString(),
                    StartDateTime = DateTimeOffset.Now.AddMinutes(-DefaultValue.DefaultSecretPeriod),
                    EndDateTime = DateTimeOffset.Now.AddMinutes(DefaultValue.DefaultSecretPeriod)
                },
            };

            PasswordCredential Result = await Client.Applications[OperatorApp.Id].AddPassword.PostAsync(AddPassword);
            _logger.Information($"Created App Login for {OperatorApp.DisplayName}");
            
            return Result;
        }
        private async Task WaitForSecretAsync(ClientSecretCredential ClientSecret)
        {
            TokenRequestContext Context = new  TokenRequestContext(DefaultValue.AzureDefaultPermission.ToArray());
            AccessToken Token = new AccessToken();
            
            while (Token.Token is null)
            {
                try
                {
                    Token = await ClientSecret.GetTokenAsync(Context);
                }
                catch (AuthenticationFailedException exception)
                {
                    await Task.Delay(DefaultValue.DefaultWaitTime);
                    _logger.Information($"Secret not active waiting for 1 sec");
                }
            }
        }
        private async Task WaitForGraphServiceClientAsync(GraphServiceClient Client)
        {
            OrganizationCollectionResponse Response = null;
            
            while (Response is null)
            {
                try
                {
                    Response = await Client.Organization.GetAsync();
                }
                catch (AuthenticationFailedException exception)
                {
                    _logger.Information("Secret is active but not published waiting");
                    await Task.Delay(DefaultValue.DefaultWaitTime);
                }
            }
        }
    }
}
