using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Class.Azure.MFA;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog.Core;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Reflection;
using System.Text.Json;
using IRH.Lib;
using IRH.Lib.Model.Azure.Result;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.Auth;

namespace IRH.Commands.Azure.MFA
{
    internal class AzureMFACommand
    {
        private const string _commandName = "-AMFA";
        private const string _commandDescription = "Get All Users and there MFA Count and Print";

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by whitespace";
        private const string _filterOnGroupAlias = "--Group";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = DefaultValue.AzureMfaPermissions.ToArray();

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLI;

        private const string _printLevel = "-PL";
        private const string _printLevelDescription = "How detailed to be printed";
        private const string _printLevelAlias = "--PrintLevel";
        private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

        //private const string _globalAppIDName = "A";
        //private const string _globalTenantIDName = "T";
        //private const string _globalAuthClientProviderName = "AU";

        private readonly Logger _logger;

        internal AzureMFACommand(Logger Logger)
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
                DefaultValueFactory = (result) => new string[] {}
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

                AzureMFA AzureMFA = new AzureMFA(_logger);

                List<UserMFA> AllUsers = await AzureMFA.GetAllUsersMFA(Client, Users);

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

        private async Task PrintResult(List<UserMFA> Result, ReportPrintLevel Level)
        {
            foreach (UserMFA SingleUser in Result)
            {
                _logger.Information($"User: {SingleUser.User.UserPrincipalName} -> Count {SingleUser.AllMFACount})");

                if (Level == ReportPrintLevel.Info || Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                {
                    foreach (AzureAuthenticationMethod SingleMethod in SingleUser.MFA)
                    {
                        _logger.Information($" | {SingleMethod.Method.GetType().ToString().Split(".").Last()}");
                        if (Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                        {
                            PropertyInfo[] AllProperties = SingleMethod.Method.GetType().GetProperties();
                            IEnumerable<PropertyInfo> AllStringVal = AllProperties.Where(prop => prop.PropertyType.Name.Equals("String"));

                            foreach (PropertyInfo StringVal in AllStringVal)
                            {
                                string Value = (string)StringVal.GetValue(SingleMethod.Method);
                                if (Value is not null)
                                {
                                    _logger.Information($" | |{StringVal.Name}: {Value}");
                                }
                            }

                            if (Level == ReportPrintLevel.Hacky)
                            {
                                IEnumerable<PropertyInfo> AllNonStringVal = AllProperties.Where(prop => !prop.PropertyType.Name.Equals("String"));

                                foreach (PropertyInfo NonStringVal in AllNonStringVal)
                                {
                                    object Value = NonStringVal.GetValue(SingleMethod.Method);
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
