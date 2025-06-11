using IRH.Commands.Azure.Helper;
using IRH.Commands.Azure.Reporting;
using IRH.Commands.Azure.Reporting.Model;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Users.Item.RevokeSignInSessions;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace IRH.Commands.Azure.Session
{
    internal class AzureSession
    {
        private const string _commandName = "-Session";
        private const string _commandDescription = "Revoke single User Session or All";

        //private const string _revokeType = "-TY";
        //private const string _revokeTypeDescription = "What type of Revoke to do";
        //private const string _revokeTypeAlias = "--RevokeType";
        //private const bool _revokeTypeIsRequired = true;

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by whitespace";
        private const string _filterOnGroupAlias = "--Group";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = new string[] { "Directory.Read.All", "User.RevokeSessions.All" };

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLI;

        private const string _printLevel = "-PL";
        private const string _printLevelDescription = "How detailed to be printed";
        private const string _printLevelAlias = "--PrintLevel";
        private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

        private const string _globalAppIDName = "A";
        private const string _globalTenantIDName = "T";
        private const string _globalAuthClientProviderName = "AU";

        private readonly Logger _logger;

        internal AzureSession(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);
            //Option<SessionRevokeType> RevokeType = new Option<SessionRevokeType>(name: _revokeType, description: _revokeTypeDescription);
            Option<string[]> Group = new Option<string[]>(name: _filterOnGroup, description: _filterOnGroupDescription);
            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
            Option<ReportType> ReportTypeOption = new Option<ReportType>(name: _reportType, description: _reportTypeDescription);
            Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, description: _printLevelDescription);

            Group.AllowMultipleArgumentsPerToken = true;
            Scopes.AllowMultipleArgumentsPerToken = true;

            //RevokeType.AddAlias(_revokeTypeAlias);
            Group.AddAlias(_filterOnGroupAlias);
            Scopes.AddAlias(_permissionScopesAlias);
            ReportTypeOption.AddAlias(_reportTypeAlias);
            PrintLevel.AddAlias(_printLevelAlias);

            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
            ReportTypeOption.SetDefaultValue(_reportTypeDefaultValue);
            PrintLevel.SetDefaultValue(_printLevelDefaultValue);

            //RevokeType.IsRequired = _revokeTypeIsRequired;

            //Command.AddOption(RevokeType);
            Command.AddOption(Group);
            Command.AddOption(Scopes);
            Command.AddOption(ReportTypeOption);
            Command.AddOption(PrintLevel);

            Command.SetHandler(async (Context) =>
            {
                ParseResult Parser = Context.ParseResult;
                CommandResult AzureCommandResult = Parser.CommandResult.Parent as CommandResult;
                Option<string> AppID = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalAppIDName)).First() as Option<string>;
                Option<string> TenantID = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalTenantIDName)).First() as Option<string>;
                Option<AuthType> AuthProviderType = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalAuthClientProviderName)).First() as Option<AuthType>;

                AzureAuth Auth = new AzureAuth();

                GraphServiceClient Client = Auth.GetClient(
                    Parser.GetValueForOption(AppID),
                    Parser.GetValueForOption(TenantID),
                    Parser.GetValueForOption(Scopes),
                    Parser.GetValueForOption(AuthProviderType)
                    );

                AzureUser AzureUser = new AzureUser(_logger);
                UserCollectionResponse Users = await AzureUser.GetUsersAsync(Client, Parser.GetValueForOption(Group));

                List<UserSession> AllUsers = await ResetUserSessionsAsync(Client, Users);
                  
                switch (Parser.GetValueForOption(ReportTypeOption))
                {
                    case ReportType.CLI:
                        await PrintResult(AllUsers, Parser.GetValueForOption(PrintLevel));
                        await ExportToJson(AllUsers);
                        break;
                    case ReportType.Json:
                        await ExportToJson(AllUsers);
                        break;
                    case ReportType.CLIAndJson:
                        await PrintResult(AllUsers, Parser.GetValueForOption(PrintLevel));
                        await ExportToJson(AllUsers);
                        break;
                }
            });

            return Command;
        }

        private async Task<List<UserSession>> ResetUserSessionsAsync(GraphServiceClient Client, UserCollectionResponse AllUsers)
        {
            List<UserSession> Result = new List<UserSession>();
            _logger.Information($"Start reseting RefreshToken for {AllUsers.Value.Count} Users");

            int Count = 1;

            foreach (User SingleUser in AllUsers.Value)
            {

                RevokeSignInSessionsPostResponse SingleUserResetResult = await Client.Users[SingleUser.Id].RevokeSignInSessions.PostAsRevokeSignInSessionsPostResponseAsync();

                UserSession SingleUserResult = new UserSession()
                {
                    User = SingleUser,
                    ResetToken = SingleUserResetResult.Value.Value,
                    Response = SingleUserResetResult
                };

                Result.Add(SingleUserResult);
                _logger.Information($"Process Revokation {Count} from {AllUsers.Value.Count}");
                Count++;
            }

            return Result;
        }

        private async Task PrintResult(List<UserSession> Result, ReportPrintLevel Level)
        {
            foreach (UserSession SingleUser in Result)
            {
                _logger.Information($"User: {SingleUser.User.UserPrincipalName} -> Revoke Status: {SingleUser.ResetToken}");

                if (Level == ReportPrintLevel.Info || Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                {
                    //NO Info level
                    if (Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                    {
                        //No Detailed level

                        if (Level == ReportPrintLevel.Hacky)
                        {
                            //No Hacky level
                        }
                    }
                }
            }
        }

        private async Task ExportToJson(List<UserSession> Result)
        {
            _logger.Information("Converting List into Json");
            using (MemoryStream Stream = new MemoryStream())
            {
                await JsonSerializer.SerializeAsync(Stream, Result);
                string FilePath = Path.Combine(Path.GetTempPath(), Path.GetTempFileName());

                using (FileStream FileStream = new FileStream(FilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    Stream.Position = 0;
                    await Stream.CopyToAsync(FileStream);

                    _logger.Information($"Result saved to {FilePath}");
                }
            }
        }
    }
}
