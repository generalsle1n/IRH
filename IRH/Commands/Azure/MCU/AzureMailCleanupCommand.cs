//using IRH.Lib;
//using IRH.Lib.Class.Azure.Auth;
//using IRH.Lib.Model.Azure.Reporting;
//using Serilog.Core;
//using System;
//using System.Collections.Generic;
//using System.CommandLine;
//using System.CommandLine.Parsing;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace IRH.Commands.Azure.MCU
//{
//    internal class AzureMailCleanupCommand
//    {
//        private const string _commandName = "-MCU";
//        private const string _commandDescription = "Delete Mails from Tenant that match th filter";

//        private const string _permissionScopes = "-P";
//        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
//        private const string _permissionScopesAlias = "--PermissionScope";
//        private string[] _permissionScopesDefaultValue = DefaultValue.AzureMailCleanupPermissions.ToArray();

//        //private const string _reportType = "-R";
//        //private const string _reportTypeDescription = "How to Report the Data";
//        //private const string _reportTypeAlias = "--Report";
//        //private const ReportType _reportTypeDefaultValue = ReportType.CLI;

//        //private const string _printLevel = "-PL";
//        //private const string _printLevelDescription = "How detailed to be printed";
//        //private const string _printLevelAlias = "--PrintLevel";
//        //private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

//        private const string _globalAppIDName = "A";
//        private const string _globalTenantIDName = "T";
//        private const string _globalAuthClientProviderName = "AU";

//        private readonly Logger _logger;
//        internal AzureMailCleanupCommand(Logger Logger)
//        {
//            _logger = Logger;
//        }

//        internal Command CreateCommand(RootCommand RootCommand)
//        {
//            Command Command = new Command(name: _commandName, description: _commandDescription);
//            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, description: _permissionScopesDescription);
//            //Option<ReportType> ReportTypeOption = new Option<ReportType>(name: _reportType, description: _reportTypeDescription);
//            //Option<ReportPrintLevel> PrintLevel = new Option<ReportPrintLevel>(name: _printLevel, description: _printLevelDescription);

//            Scopes.AllowMultipleArgumentsPerToken = true;

//            Scopes.AddAlias(_permissionScopesAlias);
//            //ReportTypeOption.AddAlias(_reportTypeAlias);
//            //PrintLevel.AddAlias(_printLevelAlias);

//            Scopes.SetDefaultValue(_permissionScopesDefaultValue);
//            //ReportTypeOption.SetDefaultValue(_reportTypeDefaultValue);
//            //PrintLevel.SetDefaultValue(_printLevelDefaultValue);

//            Command.AddOption(Scopes);
//            //Command.AddOption(ReportTypeOption);
//            //Command.AddOption(PrintLevel);

//            Command.SetHandler(async (Context) =>
//            {
//                //ParseResult Parser = Context.ParseResult;
//                //CommandResult AzureCommandResult = Parser.CommandResult.Parent as CommandResult;
//                //Option<string> AppID = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalAppIDName)).First() as Option<string>;
//                //Option<string> TenantID = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalTenantIDName)).First() as Option<string>;
//                //Option<AuthType> AuthProviderType = AzureCommandResult.Command.Options.Where(id => id.Name.Equals(_globalAuthClientProviderName)).First() as Option<AuthType>;

//                //AzureAuth Auth = new AzureAuth(_logger);

//                //GraphServiceClient Client = Auth.GetClient(
//                //    Parser.GetValueForOption(AppID),
//                //    Parser.GetValueForOption(TenantID),
//                //    Parser.GetValueForOption(Scopes),
//                //    Parser.GetValueForOption(AuthProviderType)
//                //    );
//            });

//            return Command;
//        }
//    }
//}
