using IRH.Lib;
using IRH.Lib.Model.Deployment.Esxi;
using IRH.Lib.Model.Remote.CopyFile;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Serilog.Core;

namespace IRH.Commands.Deployment.Esxi
{
    internal class EsxiDeploymentCommand
    {
        private const string CommandName = "-E";
        private const string CommandDescription = "Deploy an Program to an ESXI";
        private const string CommandAlias = "--ESXI";

        private const string DeploymentTypeName = "-T";
        private const string DeploymentTypeDescription = "Configure the deployment type which should be used to deploy the program";
        private const string DeploymentTypeAlias = "--Type";
        private readonly DeploymentType DeploymentTypeDefaultValue = DefaultValue.EsxiDeploymentType;

        private const string EsxiAdressName = "-A";
        private const string EsxiAdressDescription = "Emter the address (just Hostname or IP without http/s or path)";
        private const string EsxiAdressAlias = "--Address";
        private const bool EsxiAdressIsRequired = true;

        private const string EsxiUserName = "-UE";
        private const string EsxiUserDescription = @"Enter the user for the esxi";
        private const string EsxiUserAlias = "--UserEsxi";
        private const bool EsxiUserIsRequired = true;

        private const string EsxiPasswordName = "-PE";
        private const string EsxiPasswordDescription = @"Enter the Password for the esxi";
        private const string EsxiPasswordAlias = "--PasswordEsxi";
        private const bool EsxiPasswordIsRequired = true;

        private const string GuestUserName = "-UG";
        private const string GuestUserDescription = @"Enter the user for the guest os";
        private const string GuestUserAlias = "--UserGuest";
        private const bool GuestUserIsRequired = true;

        private const string GuestPasswordName = "-PG";
        private const string GuestPasswordDescription = @"Enter the Password for the guest os";
        private const string GuestPasswordAlias = "--PasswordGuest";
        private const bool GuestPasswordIsRequired = true;

        private const string DeploymentFileName = "-F";
        private const string DeploymentFileDescription = @"Enter the FilePath to deploy in the guest os";
        private const string DeploymentFileAlias = "--File";
        private const bool DeploymentFileIsRequired = true;

        private readonly Logger _logger;

        internal EsxiDeploymentCommand(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: CommandName, description: CommandDescription)
            {
                Aliases =
                {
                    CommandAlias
                }
            };

            Option<DeploymentType> DeploymentTypeOption = new Option<DeploymentType>(name: DeploymentTypeName, aliases: DeploymentTypeAlias)
            {
                Description = DeploymentTypeDescription,
                DefaultValueFactory = (result) => DeploymentTypeDefaultValue
            };

            Option<string> EsxiAdressOption = new Option<string>(name: EsxiAdressName, aliases: EsxiAdressAlias)
            {
                Description = EsxiAdressDescription,
                Required = EsxiAdressIsRequired
            };

            Option<string> EsxiUserOption = new Option<string>(name: EsxiUserName, aliases: EsxiUserAlias)
            {
                Description = EsxiUserDescription,
                Required = EsxiUserIsRequired
            };

            Option<string> EsxiPasswordOption = new Option<string>(name: EsxiPasswordName, aliases: EsxiPasswordAlias)
            {
                Description = EsxiPasswordDescription,
                Required = EsxiPasswordIsRequired
            };

            Option<string> GuestUserOption = new Option<string>(name: GuestUserName, aliases: GuestUserAlias)
            {
                Description = GuestUserDescription,
                Required = GuestUserIsRequired
            };

            Option<string> GuestPasswordOption = new Option<string>(name: GuestPasswordName, aliases: GuestPasswordAlias)
            {
                Description = GuestPasswordDescription,
                Required = GuestPasswordIsRequired
            };

            Option<FileInfo> DeploymentFileOption = new Option<FileInfo>(name: DeploymentFileName, aliases: DeploymentFileAlias)
            {
                Description = DeploymentFileDescription,
                Required = DeploymentFileIsRequired
            };

            Command.Options.Add(DeploymentTypeOption);
            Command.Options.Add(EsxiAdressOption);
            Command.Options.Add(EsxiUserOption);
            Command.Options.Add(EsxiPasswordOption);
            Command.Options.Add(GuestUserOption);
            Command.Options.Add(GuestPasswordOption);
            Command.Options.Add(DeploymentFileOption);

            return Command;
        }
    }
}
