using IRH.Commands.Azure.MCU.Model;
using IRH.Lib;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.Mail;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Mail;
using IRH.Lib.Model.Azure.Reporting;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog.Core;
using System.CommandLine;
using System.Text.Json;

namespace IRH.Commands.Azure.MCU
{
    internal class AzureMailCommand
    {
        private const string _commandName = "-MCU";
        private const string _commandDescription = "Work with Mails from Tenant that match the filter";

        private const string _permissionScopes = "-P";
        private const string _permissionScopesDescription = "Enter the custom permission to access the api, serpated by whitespace";
        private const string _permissionScopesAlias = "--PermissionScope";
        private string[] _permissionScopesDefaultValue = DefaultValue.AzureMailCleanupPermissions.ToArray();

        private const string _mailAction = "-AC";
        private const string _mailActionDescription = "Set the Mode --> Preview just view | Delete view and delete data";
        private const string _mailActionAlias = "--Action";
        private const MailAction _mailActionDefaultValue = MailAction.Preview;
        private const bool _mailActionIsRequired = true;

        private const string _filterOnGroup = "-G";
        private const string _filterOnGroupDescription = "Enter the ID for the Group or multiple seperated by whitespace";
        private const string _filterOnGroupAlias = "--Group";

        private const string _subjectFilter = "-FS";
        private const string _subjectFilterDescription = "Filter for mails that match the subject (There can be multiple Values applied seperated by whitespace)";
        private const string _subjectFilterAlias = "--FilterSubject";

        private const string _startDateFilter = "-FSD";
        private const string _startDateFilterDescription = "Enter the Start of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _startDateFilterAlias = "--FilterStart";
        private DateTime _startDateFilterDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);

        private const string _endDateFilter = "-FED";
        private const string _endDateFilterDescription = "Enter the End of the Investigation (Just in Format DD.MM.YYYY)";
        private const string _endDateFilterAlias = "--FilterEnd";
        private DateTime _endDateFilterDefaultValue = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day).AddDays(2).AddTicks(-1);

        private const string _reportType = "-R";
        private const string _reportTypeDescription = "How to Report the Data";
        private const string _reportTypeAlias = "--Report";
        private const ReportType _reportTypeDefaultValue = ReportType.CLI;

        private const string _printLevel = "-PL";
        private const string _printLevelDescription = "How detailed to be printed";
        private const string _printLevelAlias = "--PrintLevel";
        private const ReportPrintLevel _printLevelDefaultValue = ReportPrintLevel.Brief;

        private readonly Logger _logger;

        internal AzureMailCommand(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string[]> Scopes = new Option<string[]>(name: _permissionScopes, aliases: _permissionScopesAlias)
            {
                Description = _permissionScopesDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => _permissionScopesDefaultValue
            };

            Option<MailAction> MailActionOption = new Option<MailAction>(name: _mailAction, aliases: _mailActionAlias)
            {
                Description = _mailActionDescription,
                DefaultValueFactory = (result) => _mailActionDefaultValue,
                Required = _mailActionIsRequired
            };

            Option<string[]> Group = new Option<string[]>(name: _filterOnGroup, aliases: _filterOnGroupAlias)
            {
                Description = _filterOnGroupDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => new string[] {}
            };

            Option<string[]> FilterSubjectOption = new Option<string[]>(name: _subjectFilter, aliases: _subjectFilterAlias)
            {
                Description = _subjectFilterDescription,
                AllowMultipleArgumentsPerToken = true,
            };

            Option<DateTime> FilterStartDateOption = new Option<DateTime>(name: _startDateFilter, aliases: _startDateFilterAlias)
            {
                Description = _startDateFilterDescription,
                DefaultValueFactory = (result) => _startDateFilterDefaultValue,
            };

            Option<DateTime> FilterEndDateOption = new Option<DateTime>(name: _endDateFilter, aliases: _endDateFilterAlias)
            {
                Description = _endDateFilterDescription,
                DefaultValueFactory = (result) => _endDateFilterDefaultValue,
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

            Command.Options.Add(Scopes);
            Command.Options.Add(MailActionOption);
            Command.Options.Add(Group);
            Command.Options.Add(FilterSubjectOption);
            Command.Options.Add(FilterStartDateOption);
            Command.Options.Add(FilterEndDateOption);
            Command.Options.Add(ReportTypeOption);
            Command.Options.Add(PrintLevel);

            Command.SetAction(async parseResult =>
            {
                //Todo: Implement Event Meeting support
                //Todo: Implement Just single user
                //Todo: Implement Group support
                //Todo: Add Regex support

                AzureAuth Auth = new AzureAuth(_logger);

                GraphServiceClient Client = await Auth.GetClientAsync(
                    parseResult.GetRequiredValue<string>(AzureFunctions._publicAppID),
                    parseResult.GetRequiredValue<string>(AzureFunctions._publicTenantID),
                    DefaultValue.AzureAppRegistrationPermissions.ToArray(),
                    parseResult.GetRequiredValue<AuthType>(AzureFunctions._authClientProvider),
                    ElevateToAppAccess: true,
                    ElevatePermission: parseResult.GetRequiredValue(Scopes)
                );

                AzureUser AzureUser = new AzureUser(_logger);
                UserCollectionResponse Users = await AzureUser.GetUsersAsync(Client, parseResult.GetRequiredValue(Group));

                AzureMail AzureMail = new AzureMail(_logger);
                List<UserMailCollection> UserMailCollection = await AzureMail.GetMails(Client, Users,parseResult.GetValue(FilterSubjectOption), parseResult.GetRequiredValue(FilterStartDateOption), parseResult.GetRequiredValue(FilterEndDateOption));

                if(parseResult.GetRequiredValue(MailActionOption) == MailAction.Delete)
                {
                    _logger.Information($"Mail Action is set to Delete, start delete");
                    foreach (UserMailCollection SingleUser in UserMailCollection)
                    {
                        await AzureMail.DeleteMails(Client, SingleUser);
                        SingleUser.Deleted = true;
                    }
                }

                switch (parseResult.GetRequiredValue(ReportTypeOption))
                {
                    case ReportType.CLI:
                        await PrintResult(UserMailCollection, parseResult.GetRequiredValue(PrintLevel));
                        break;
                    case ReportType.Json:
                        await ExportToJson(UserMailCollection);
                        break;
                    case ReportType.CLIAndJson:
                        await PrintResult(UserMailCollection, parseResult.GetRequiredValue(PrintLevel));
                        await ExportToJson(UserMailCollection);
                        break;
                }
            });

            return Command;
        }

        private async Task PrintResult(List<UserMailCollection> Result, ReportPrintLevel Level)
        {
            IEnumerable<IGrouping<string, UserMailCollection>> userGrouped = Result.GroupBy(user => user.User.UserPrincipalName);
            foreach (IGrouping<string, UserMailCollection> SingleUser in userGrouped)
            {
                _logger.Information($"User: {SingleUser.Key} -> Count Mails {SingleUser.Count()})");

                if (Level == ReportPrintLevel.Info || Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                {
                    foreach (UserMailCollection SingleMailStatus in SingleUser)
                    {
                        _logger.Information($" | Subject: {SingleMailStatus.MailStatus.Mail.Subject} - Received: {SingleMailStatus.MailStatus.Mail.ReceivedDateTime} - From: {SingleMailStatus.MailStatus.Mail.Sender.EmailAddress.Address}");
                        if (Level == ReportPrintLevel.Detailed || Level == ReportPrintLevel.Hacky)
                        {
                            _logger.Information($" | | Has Attachment: {SingleMailStatus.MailStatus.Mail.HasAttachments} - Was Read: {SingleMailStatus.MailStatus.Mail.IsRead}");
                            if (Level == ReportPrintLevel.Hacky)
                            {
                                _logger.Information($" | | | Id: {SingleMailStatus.MailStatus.Mail.Id}");
                            }
                        }
                    }
                }
            }
        }

        private async Task ExportToJson(List<UserMailCollection> Result)
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