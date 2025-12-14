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
        private const string DeploymentFileDescription = @"Enter the FilePath to deploy in the guest os (When set Deployment Type to -T RawCmd you still need to set this option (its not copied to the guest :D its needed for the command line libary to be parsed))";
        private const string DeploymentFileAlias = "--File";
        private const bool DeploymentFileIsRequired = true;

        private const string GuestOsSelectionName = "-G";
        private const string GuestOsSelectionDescription = @"Enter the Guest os to deploy the setup";
        private const string GuestOsSelectionAlias = "--Guest";
        private const GuestOs GuestOsSelectionDefaultValue = GuestOs.Windows;

        private const string GuestOsMsiExecArgumentName = "-AM";
        private const string GuestOsMsiExecArgumentDescription = @"Enter the custom argument which is appended at the end like this (msiexec /I setup.msi YOURE ARGUMENT)";
        private const string GuestOsMsiExecArgumentAlias = "--ArgumentMsi";
        private const string GuestOsMsiExecArgumentDefaultValue = DefaultValue.DefaultWindowsMsiExecSuffixArguments;

        private const string GuestOsExeArgumentName = "-AE";
        private const string GuestOsExeArgumentDescription = @"Enter the custom argument which is appended at the end like this (setup.exe YOURE ARGUMENT)";
        private const string GuestOsExeArgumentAlias = "--ArgumentExe";
        private const string GuestOsExeArgumentDefaultValue = DefaultValue.DefaultWindowsExeSuffixArguments;

        private const string GuestOsRawCmdArgumentName = "-AC";
        private const string GuestOsRawCmdArgumentDescription = @"Enter the custom argument which is executed on the guest directly (cmd.exe /C)";
        private const string GuestOsRawCmdArgumentAlias = "--ArgumentCmd";

        private const string ExcludeVMsByNameName = "-FE";
        private const string ExcludeVMsByNameDescription = @"Enter names from the vms which should be excluded by the deployment process (You can enter multiple serpated by whitespace), when include and exclude are set the include is processed first and then exclude";
        private const string ExcludeVMsByNameAlias = "--FilterExclude";
        private readonly List<string> ExcludeVMsByNameDefaultValue = new List<string>();

        private const string IncludeVMsByNameName = "-FI";
        private const string IncludeVMsByNameDescription = @"Enter names from the vms which should be included by the deployment process (You can enter multiple serpated by whitespace), when include and exclude are set the include is processed first and then exclude";
        private const string IncludeVMsByNameAlias = "--FilterInclude";
        private readonly List<string> IncludeVMsByNameDefaultValue = new List<string>();

        private const string NewVMNetworkName = "-VMN";
        private const string NewVMNetworkDescription = @"Enter the name of the vnet which the virtualmachine should be assigned (When this setting is configured the client is set to dhcp (ip + dns))";
        private const string NewVMNetworkAlias = "--VirtualMachineNetwork";

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
                Required = false,
                DefaultValueFactory = (result) => null
            };

            DeploymentFileOption.Validators.Add(result =>
            {
                DeploymentType selectedDeployment = result.GetRequiredValue<DeploymentType>(DeploymentTypeOption);
                FileInfo file = result.GetRequiredValue<FileInfo>(DeploymentFileOption);

                if(selectedDeployment != DeploymentType.RawCmd)
                {
                    if(file is null)
                    {
                        result.AddError($"-F is empty please set to an file which should be deployed");
                    }
                }
            });

            Option<GuestOs> GuestOsSelectionOption = new Option<GuestOs>(name: GuestOsSelectionName, aliases: GuestOsSelectionAlias)
            {
                Description = GuestOsSelectionDescription,
                DefaultValueFactory = (result) => GuestOsSelectionDefaultValue
            };

            Option<string> GuestOsMsiExecArgumentOption = new Option<string>(name: GuestOsMsiExecArgumentName, aliases: GuestOsMsiExecArgumentAlias)
            {
                Description = GuestOsMsiExecArgumentDescription,
                DefaultValueFactory = (result) => GuestOsMsiExecArgumentDefaultValue
            };

            Option<string> GuestOsExeArgumentOption = new Option<string>(name: GuestOsExeArgumentName, aliases: GuestOsExeArgumentAlias)
            {
                Description = GuestOsExeArgumentDescription,
                DefaultValueFactory = (result) => GuestOsExeArgumentDefaultValue
            };

            Option<string> GuestOsRawCmdArgumentOption = new Option<string>(name: GuestOsRawCmdArgumentName, aliases: GuestOsRawCmdArgumentAlias)
            {
                Description = GuestOsRawCmdArgumentDescription,
                DefaultValueFactory = (result) => string.Empty
            };

            GuestOsRawCmdArgumentOption.Validators.Add(result =>
            {
                DeploymentType selectedDeployment = result.GetRequiredValue<DeploymentType>(DeploymentTypeOption);
                string rawCmdArgument = result.GetRequiredValue<string>(GuestOsRawCmdArgumentOption);

                if(selectedDeployment == DeploymentType.RawCmd)
                {
                    if(string.IsNullOrEmpty(rawCmdArgument))
                    {
                        result.AddError($"When deployment type is set to RawCmd you need to specify an argument {GuestOsRawCmdArgumentName} which is executed on the guest os directly");
                    }
                }
            });

            Option<List<string>> ExcludeVMsByNameOption = new Option<List<string>>(name: ExcludeVMsByNameName, aliases: ExcludeVMsByNameAlias)
            {
                Description = ExcludeVMsByNameDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => ExcludeVMsByNameDefaultValue
            };
            
            Option<List<string>> IncludeVMsByNameOption = new Option<List<string>>(name: IncludeVMsByNameName, aliases: IncludeVMsByNameAlias)
            {
                Description = IncludeVMsByNameDescription,
                AllowMultipleArgumentsPerToken = true,
                DefaultValueFactory = (result) => IncludeVMsByNameDefaultValue
            };

            Option<string> NewVMNetworkOption = new Option<string>(name: NewVMNetworkName, aliases: NewVMNetworkAlias)
            {
                Description = NewVMNetworkDescription
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
            Command.Options.Add(GuestOsMsiExecArgumentOption);
            Command.Options.Add(GuestOsExeArgumentOption);
            Command.Options.Add(GuestOsRawCmdArgumentOption);
            Command.Options.Add(ExcludeVMsByNameOption);
            Command.Options.Add(IncludeVMsByNameOption);
            Command.Options.Add(NewVMNetworkOption);

            Command.SetAction(async parseResult =>
            {
                List<string> userNameList = parseResult.GetRequiredValue<List<string>>(GuestUserOption);
                List<string> passwordList = parseResult.GetRequiredValue<List<string>>(GuestPasswordOption);
                string newVmNetwork = parseResult.GetValue<string>(NewVMNetworkOption) ?? string.Empty;

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
                    List<VirtualMachine> FilteredData = await EsxiDeployment.FilterVMsAsync(navigation, AllData, parseResult.GetRequiredValue<GuestOs>(GuestOsSelectionOption), parseResult.GetRequiredValue<List<string>>(ExcludeVMsByNameOption), parseResult.GetRequiredValue<List<string>>(IncludeVMsByNameOption));

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
                        List<VirtualMachine> processedVms = new List<VirtualMachine>();

                        foreach (VirtualMachine singleVm in FilteredData)
                        {
                            DeploymentType selectedDeployment = parseResult.GetRequiredValue<DeploymentType>(DeploymentTypeOption);
                            VirtualMachine vm = null;

                            if (!newVmNetwork.Equals(string.Empty))
                            {
                                _logger.Information($"VM Network config is set so network is changed to {newVmNetwork}");
                                await EsxiDeployment.SetVMNetworkByNameAsync(navigation, singleVm, parseResult.GetRequiredValue<string>(NewVMNetworkOption));
                            }

                            if (DeploymentType.RawCmd != selectedDeployment)
                            {
                                vm = await EsxiDeployment.CopyFileToVMAsync(navigation, loginData, singleVm, parseResult.GetRequiredValue<GuestOs>(GuestOsSelectionOption), parseResult.GetRequiredValue<FileInfo>(DeploymentFileOption), httpClient);
                            }
                            
                            switch (parseResult.GetRequiredValue<DeploymentType>(DeploymentTypeOption))
                            {
                                case DeploymentType.MSIExec:
                                    await EsxiDeployment.InstalMsiOnVMAsync(navigation, vm, parseResult.GetRequiredValue<string>(GuestOsMsiExecArgumentOption));
                                    break;
                                case DeploymentType.Exe:
                                    await EsxiDeployment.InstallExeOnVMAsync(navigation, vm, parseResult.GetRequiredValue<string>(GuestOsExeArgumentOption));
                                    break;
                                case DeploymentType.RawCmd:
                                    await EsxiDeployment.ExecuteCmdOnVMAsync(navigation, singleVm, loginData, parseResult.GetRequiredValue<string>(GuestOsRawCmdArgumentOption));
                                    break;
                                default:
                                    _logger.Error($"Deployment type {parseResult.GetRequiredValue<DeploymentType>(DeploymentTypeOption)} not supported");
                                    break;
                            }

                            processedVms.Add(vm);
                        }
                        await ExportToJson(processedVms);
                    }
                }
                else
                {
                    _logger.Error($"Found not matching amount username {userNameList.Count} and password {passwordList.Count}");
                }
            });

            return Command;
        }
        private async Task ExportToJson(List<VirtualMachine> Result)
        {
            _logger.Information("Converting List into Json");
            using (MemoryStream Stream = new MemoryStream())
            {
                await JsonSerializer.SerializeAsync(Stream, Result);
                string FilePath = Path.GetTempFileName();

                using (FileStream FileStream = new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite))
                {
                    Stream.Position = 0;
                    await Stream.CopyToAsync(FileStream);

                    _logger.Information($"Result saved to {FilePath}");
                }
            }
        }
    }
}
