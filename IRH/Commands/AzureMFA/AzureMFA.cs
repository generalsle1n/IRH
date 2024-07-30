using Azure.Identity;
using IRH.Commands.AzureMFA.Reporting;
using IRH.Commands.AzureMFA.Reporting.Model;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog.Core;
using System.CommandLine;
using System.Reflection;
using System.Text.Json;

namespace IRH.Commands.LDAPMonitor
{
    internal class AzureMFA
    {
        private const string _commandName = "-AMFA";
        private const string _commandDescription = "Get All Users and there MFA Count and Print";

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by whitespace";
        private const string _filterOnGroupAlias = "--Group";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = new string[] { "Directory.Read.All", "UserAuthenticationMethod.Read.All" };

        private const string _publicAppID = "-A";
        private const string _publicAppIDDescription = "Enter the ID of the App ID";
        private const string _publicAppIDAlias = "--AppID";
        private const bool _publicAppIDIsRequired = true;

        private const string _publicTenantID = "-T";
        private const string _publicTenantIDDescription = "Enter the ID of the Tenant ID (In the default you dont need to change this)";
        private const string _publicTenantIDAlias = "--Tenant";
        private const string _publicTenantIDDefaultValue = "common";

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLI;

        private const string _printLevel = "-PL";
        private const string _printLevelDescription = "How detailed to be printed";
        private const string _printLevelAlias = "--PrintLevel";
        private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

        private readonly Logger _logger;

        internal AzureMFA(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Group = new Option<string[]>(name: _filterOnGroup, description: _filterOnGroupDescription);
            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
            Option<string> AppID = new Option<string>(name: _publicAppID, description: _publicAppIDDescription);
            Option<string> TenantID = new Option<string>(name: _publicTenantID, description: _publicTenantIDDescription);
            Option<string> ReportType = new Option<string>(name: _reportType, description: _reportTypeDescription);
            Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, description: _printLevelDescription);

            AppID.IsRequired = _publicAppIDIsRequired;

            Group.AllowMultipleArgumentsPerToken = true;
            Scopes.AllowMultipleArgumentsPerToken = true;

            Group.AddAlias(_filterOnGroupAlias);
            Scopes.AddAlias(_permissionScopesAlias);
            AppID.AddAlias(_publicAppIDAlias);
            TenantID.AddAlias(_publicTenantIDAlias);
            ReportType.AddAlias(_reportTypeAlias);
            PrintLevel.AddAlias(_printLevelAlias);

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            TenantID.SetDefaultValue(_publicTenantIDDefaultValue);
            ReportType.SetDefaultValue(_reportTypeDefaultValue);
            PrintLevel.SetDefaultValue(_printLevelDefaultValue);
                
            Command.AddOption(Group);
            Command.AddOption(Scopes);
            Command.AddOption(AppID);
            Command.AddOption(TenantID);
            Command.AddOption(ReportType);
            Command.AddOption(PrintLevel);

            Command.SetHandler(async (GroupValue, ScopesValue, AppIDValue, TenantIDValue, ReportTypeValue, PrintLevelValue) =>
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

                await GetUsers(Client, GroupValue);

            }, Group, Scopes, AppID, TenantID);

            }, Group, Scopes, AppID, TenantID, ReportTypeOption, PrintLevel);

            return Command;
        }

        private async Task<UserCollectionResponse> GetUsers(GraphServiceClient Client, string[] GroupIDs)
        {
            _logger.Information("Querying all Users with MemberOf Attribute, this can take some time");
            UserCollectionResponse AllUsers = await Client.Users.GetAsync((search) =>
            {
                search.QueryParameters.Expand = new string[] { "memberOf" };
            });

            if(GroupIDs.Length > 0){
                _logger.Information("Start on filtering User");
                int Count = 1;

                UserCollectionResponse CleanUser = new UserCollectionResponse();
                CleanUser.Value = new List<User>();
                foreach(User SingleUser in AllUsers.Value)
                {
                    foreach(DirectoryObject SingleGroup in SingleUser.MemberOf)
                    {
                        bool Result = GroupIDs.Contains(SingleGroup.Id);
                        if (Result)
                        {
                            CleanUser.Value.Add(SingleUser);
                            break;
                        }
                    }

                    _logger.Information($"Processed {Count} from {AllUsers.Value.Count}");
                    Count++;
                }
                return CleanUser;
            }
            else
            {
                _logger.Information($"Found {AllUsers.Value.Count} Users without Filtering");
                return AllUsers;
            }
        }
        private async Task<List<UserMFA>> GetAllUsersMFA(GraphServiceClient Client, UserCollectionResponse AllUsers)
        {
            List<UserMFA> Result = new List<UserMFA>();
            _logger.Information($"Start getting MFA Methods for {AllUsers.Value.Count} Users");

            int Count = 1;

            foreach (User SingleUser in AllUsers.Value)
            {
                AuthenticationMethodCollectionResponse AuthMethods = await Client.Users[SingleUser.Id].Authentication.Methods.GetAsync();

                UserMFA SingleUserResult = new UserMFA()
                {
                    User = SingleUser,
                    MFA = new List<AuthenticationMethod>(),
                    AllMFACount = AuthMethods.Value.Count
                };

                SingleUserResult.MFA.AddRange(AuthMethods.Value);

                Result.Add(SingleUserResult);
                _logger.Information($"Process MFA {Count} from {AllUsers.Value.Count}");
            }

            return Result;
        }


        private async Task PrintResult(List<UserMFA> Result, ReportPrintLevel Level)
        {
            foreach (UserMFA SingleUser in Result)
            {
                _logger.Information($"User: {SingleUser.User.UserPrincipalName} -> Count {SingleUser.AllMFACount})");

                if (Level == ReportPrintLevel.Info || Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                {
                    foreach (AuthenticationMethod SingleMethod in SingleUser.MFA)
                    {
                        _logger.Information($" | {SingleMethod.GetType().ToString().Split(".").Last()}");
                        if(Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                        {
                            PropertyInfo[] AllProperties = SingleMethod.GetType().GetProperties();
                            IEnumerable<PropertyInfo> AllStringVal = AllProperties.Where(prop => prop.PropertyType.Name.Equals("String"));

                            foreach(PropertyInfo StringVal in AllStringVal)
                            {
                                string Value = (string)StringVal.GetValue(SingleMethod);
                                if (Value is not null)
                                {
                                    _logger.Information($" | |{StringVal.Name}: {Value}");
                                }
                            }
                            
                            if(Level == ReportPrintLevel.Hacky)
                            {
                                IEnumerable<PropertyInfo> AllNonStringVal = AllProperties.Where(prop => !prop.PropertyType.Name.Equals("String"));

                                foreach (PropertyInfo NonStringVal in AllNonStringVal)
                                {
                                    object Value = NonStringVal.GetValue(SingleMethod);
                                    if (Value is not null)
                                    { 
                                        _logger.Information($" | | | {NonStringVal.Name}: {Value.ToString()}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private async Task ExportToJson(List<UserMFA> Result)
        {
            _logger.Information("Converting List into Json");
            string lol = JsonSerializer.Serialize(Result);
            using(MemoryStream Stream = new MemoryStream())
            {
                await JsonSerializer.SerializeAsync(Stream, Result);
                string FilePath = Path.Combine(Path.GetTempPath(), Path.GetTempFileName());

                using(FileStream FileStream = new FileStream(FilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    Stream.Position = 0;
                    await Stream.CopyToAsync(FileStream);

                    _logger.Information($"Result saved to {FilePath}");
                }
            }
        }
    }
}
