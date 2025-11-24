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
using IRH.Lib.Class.Deployment.VMWare;
using IRH.Lib.Model.General;

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
        private const string EsxiAdressDescription = "Enter the address (just Hostname or IP without http/s or path)";
        private const string EsxiAdressAlias = "--Address";
        private const bool EsxiAdressIsRequired = true;

        private const string EsxiPortName = "-P";
        private const string EsxiPortDescription = "Enter the port (TCP)";
        private const string EsxiPortAlias = "--Port";
        private const int EsxiPortDefaultValue = DefaultValue.DefaultEsxiPort;

        private const string EsxiSchemeName = "-S";
        private const string EsxiSchemeDescription = "Enter the Scheme (http/https)";
        private const string EsxiSchemeAlias = "--Scheme";
        private const WebScheme EsxiSchemeDefaultValue = WebScheme.Https;

        private const string EsxiUserName = "-UE";
        private const string EsxiUserDescription = @"Enter the user for the esxi";
        private const string EsxiUserAlias = "--UserEsxi";
        private const bool EsxiUserIsRequired = true;

        private const string EsxiPasswordName = "-PE";
        private const string EsxiPasswordDescription = @"Enter the Password for the esxi";
        private const string EsxiPasswordAlias = "--PasswordEsxi";
        private const bool EsxiPasswordIsRequired = true;

        private const string GuestUserName = "-UG";
        private const string GuestUserDescription = @"Enter the user for the guest os (You can specify more usernames seperated by whitespace, when you enter multiple the first username is tested when it not work the next one is tried, when more usernames are specified you need the same amount of password to set)";
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

        private const string GuestOsSelectionName = "-G";
        private const string GuestOsSelectionDescription = @"Enter the Guest os to deploy the setup";
        private const string GuestOsSelectionAlias = "--Guest";
        private const GuestOs GuestOsSelectionDefaultValue = GuestOs.Windows;

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

            Option<int> EsxiPortOption = new Option<int>(name: EsxiPortName, aliases: EsxiPortAlias)
            {
                Description = EsxiPortDescription,
                DefaultValueFactory = (result) => EsxiPortDefaultValue
            };

            Option<WebScheme> EsxiSchemeOption = new Option<WebScheme>(name: EsxiSchemeName, aliases: EsxiSchemeAlias)
            {
                Description = EsxiSchemeDescription,
                DefaultValueFactory = (result) => EsxiSchemeDefaultValue
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

            Option<List<string>> GuestUserOption = new Option<List<string>>(name: GuestUserName, aliases: GuestUserAlias)
            {
                Description = GuestUserDescription,
                Required = GuestUserIsRequired,
                AllowMultipleArgumentsPerToken = true
            };

            Option<List<string>> GuestPasswordOption = new Option<List<string>>(name: GuestPasswordName, aliases: GuestPasswordAlias)
            {
                Description = GuestPasswordDescription,
                Required = GuestPasswordIsRequired,
                AllowMultipleArgumentsPerToken = true
            };

            Option<FileInfo> DeploymentFileOption = new Option<FileInfo>(name: DeploymentFileName, aliases: DeploymentFileAlias)
            {
                Description = DeploymentFileDescription,
                Required = DeploymentFileIsRequired
            };

            Option<GuestOs> GuestOsSelectionOption = new Option<GuestOs>(name: GuestOsSelectionName, aliases: GuestOsSelectionAlias)
            {
                Description = GuestOsSelectionDescription,
                DefaultValueFactory = (result) => GuestOsSelectionDefaultValue
            };

            Command.Options.Add(DeploymentTypeOption);
            Command.Options.Add(EsxiAdressOption);
            Command.Options.Add(EsxiPortOption);
            Command.Options.Add(EsxiSchemeOption);
            Command.Options.Add(EsxiUserOption);
            Command.Options.Add(EsxiPasswordOption);
            Command.Options.Add(GuestUserOption);
            Command.Options.Add(GuestPasswordOption);
            Command.Options.Add(DeploymentFileOption);
            Command.Options.Add(GuestOsSelectionOption);

            Command.SetAction(async parseResult =>
            {
                List<string> userNameList = parseResult.GetRequiredValue<List<string>>(GuestUserOption);
                List<string> passwordList = parseResult.GetRequiredValue<List<string>>(GuestPasswordOption);

                if(userNameList.Count == passwordList.Count)
                {
                    EsxiDeployment EsxiDeployment = new EsxiDeployment(_logger);

                    HypervisorLoginInfo HypervisorLoginInfo = new HypervisorLoginInfo
                    {
                        Address = parseResult.GetRequiredValue<string>(EsxiAdressOption),
                        Port = parseResult.GetRequiredValue<int>(EsxiPortOption),
                        Scheme = parseResult.GetRequiredValue<WebScheme>(EsxiSchemeOption),
                        User = parseResult.GetRequiredValue<string>(EsxiUserOption),
                        Password = parseResult.GetRequiredValue<string>(EsxiPasswordOption)
                    };

                EsxiNavigation navigation = await EsxiDeployment.LoginAsync(HypervisorLoginInfo);
                
                List<VirtualMachine> AllData = await EsxiDeployment.GetAllVMsAsync(navigation);
                List<VirtualMachine> FilteredData = await EsxiDeployment.FilterVMsAsync(navigation, AllData, parseResult.GetRequiredValue<GuestOs>(GuestOsSelectionOption));
                    EsxiNavigation navigation = await EsxiDeployment.LoginAsync(HypervisorLoginInfo);

                    List<VirtualMachine> AllData = await EsxiDeployment.GetAllVMsAsync(navigation);
                    List<VirtualMachine> FilteredData = await EsxiDeployment.FilterVMsAsync(navigation, AllData, parseResult.GetRequiredValue<GuestOs>(GuestOsSelectionOption));

                    List<GuestOsLoginInfo> loginData = new List<GuestOsLoginInfo>();

                    int count = 0;

                    foreach(string userName in userNameList)
                    {
                        loginData.Add(new GuestOsLoginInfo
                        {
                            User = userName,
                            Password = passwordList[count],
                            Domain = string.Empty
                        });
                        
                        count++;
                    }

                    HttpClientHandler handler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                    };

                    using (HttpClient httpClient = new HttpClient(handler))
                    {
                        foreach (VirtualMachine singleVm in FilteredData)
                        {
                            await EsxiDeployment.CopyFileToVMAsync(navigation, loginData, singleVm, parseResult.GetRequiredValue<GuestOs>(GuestOsSelectionOption), parseResult.GetRequiredValue<FileInfo>(DeploymentFileOption), httpClient);
                        }
                    }
                }
                else
                {
                    _logger.Error($"Found not matching amount username {userNameList.Count} and password {passwordList.Count}");
                }
            });

            return Command;
        }
    }
}
