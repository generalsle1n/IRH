using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog.Core;
using System.CommandLine;
using System.Text.Json;
using IRH.Lib;
using IRH.Lib.Class.Azure.Session;
using IRH.Lib.Model.Azure.Session;

namespace IRH.Commands.Azure.Session
{
    internal class AzureSessionCommand
    {
        private const string _commandName = "-Session";
        private const string _commandDescription = "Revoke single User Session or All";

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by whitespace";
        private const string _filterOnGroupAlias = "--Group";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = DefaultValue.AzureSessionPermissions.ToArray();

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLIAndJson;

        private const string _printLevel = "-PL";
        private const string _printLevelDescription = "How detailed to be printed";
        private const string _printLevelAlias = "--PrintLevel";
        private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

        private readonly Logger _logger;

        internal AzureSessionCommand(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Group = new Option<string[]>(name: _filterOnGroup, aliases: _filterOnGroupAlias)
            {
                Description = _filterOnGroupDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => new string[] { }
            };

            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, aliases: _permissionScopesAlias)
            {
                Description = _permissionScopesDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => _permissionScopesDefaultValue
            };

            Option<ReportType> ReportTypeOption = new Option<ReportType>(name: _reportType, aliases: _reportTypeAlias)
            {
                Description = _reportTypeDescription,
                DefaultValueFactory = (result) => _reportTypeDefaultValue
            };

            Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, aliases: _printLevelAlias)
            {
                Description = _printLevelDescription,
                DefaultValueFactory = (result) => _printLevelDefaultValue
            };

            Command.Options.Add(Group);
            Command.Options.Add(Scopes);
            Command.Options.Add(ReportTypeOption);
            Command.Options.Add(PrintLevel);

            Command.SetAction(async parseResult =>
            {
                AzureAuth Auth = new AzureAuth(_logger);

                GraphServiceClient Client = Auth.GetClient(
                    parseResult.GetRequiredValue<string>(AzureFunctions._publicAppID),
                    parseResult.GetRequiredValue<string>(AzureFunctions._publicTenantID),
                    parseResult.GetRequiredValue(Scopes),
                    parseResult.GetRequiredValue<AuthType>(AzureFunctions._authClientProvider)
                    );

                AzureUser AzureUser = new AzureUser(_logger);
                UserCollectionResponse Users = await AzureUser.GetUsersAsync(Client, parseResult.GetRequiredValue(Group));

                AzureSession AzureSession = new AzureSession(_logger);

                List<UserSession> AllUsers = await AzureSession.ResetUserSessionsAsync(Client, Users);

                switch (parseResult.GetRequiredValue(ReportTypeOption))
                {
                    case ReportType.CLI:
                        await PrintResult(AllUsers, parseResult.GetRequiredValue(PrintLevel));
                        break;
                    case ReportType.Json:
                        await ExportToJson(AllUsers);
                        break;
                    case ReportType.CLIAndJson:
                        await PrintResult(AllUsers, parseResult.GetRequiredValue(PrintLevel));
                        await ExportToJson(AllUsers);
                        break;
                }
            });

            return Command;
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
