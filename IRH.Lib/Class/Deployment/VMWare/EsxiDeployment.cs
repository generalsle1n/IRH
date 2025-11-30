using IRH.Lib.Model.Deployment.Esxi;
using IRH.Lib.VMWare.Eight;
using Serilog;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Threading.Tasks;
using FileInfo = System.IO.FileInfo;

namespace IRH.Lib.Class.Deployment.VMWare
{
    public class EsxiDeployment
    {
        public EsxiDeployment(ILogger logger)
        {
            _logger = logger;
            _esxiFactory = new EsxiFactory(_logger);
        }

        private readonly ILogger _logger;
        private readonly EsxiFactory _esxiFactory;

        private readonly string[] virtualMachinePorperties = new string[] {
            DefaultValue.EsxiPropertyNameValue,
            DefaultValue.EsxiPropertyConfigUuidValue,
            DefaultValue.EsxiPropertyConfigGuestFullName,
            DefaultValue.EsxiPropertyConfigGuestIdValue,
            DefaultValue.EsxiPropertyRuntimePowerStateValue,
            DefaultValue.EsxiPropertyGuestToolsRunningStatusValue,
            DefaultValue.EsxiPropertyGuestGuestFullNameValue,
        };

        public async Task<EsxiNavigation> LoginAsync(HypervisorLoginInfo loginInfo)
        {
            _logger.Information($"Try to connect to {loginInfo.Scheme}://{loginInfo.Address}:{loginInfo.Port} with user {loginInfo.User}");
            VimPortTypeClient client = await _esxiFactory.CreateVimPortTypeClientAsync(loginInfo);

            EsxiNavigation Result = new EsxiNavigation()
            {
                Client = client
            };

            try
            {
                Result.ServiceContent = await client.RetrieveServiceContentAsync(new Lib.VMWare.Eight.ManagedObjectReference()
                {
                    type = "ServiceInstance",
                    Value = "ServiceInstance"
                });

            }
            catch(Exception ex)
            {
                _logger.Error($"Cannot retrieve service content from ESXi host at {loginInfo.Address}:{loginInfo.Port}. Exception: {ex}");
            }
            

            if(Result.ServiceContent is not null)
            {
                try
                {
                    Result.UserSession = await client.LoginAsync(Result.ServiceContent.sessionManager, loginInfo.User, loginInfo.Password, "en-us");
                    _logger.Information($"Successfully logged in to ESXi host at {loginInfo.Address}:{loginInfo.Port} as user {loginInfo.User}");
                }
                catch (Exception ex)
                {
                    _logger.Error($"Login to ESXi host at {loginInfo.Address}:{loginInfo.Port} failed for user {loginInfo.User}. Exception: {ex}");
                }
            }

            return Result;
        }

        public async Task<List<VirtualMachine>> GetAllVMsAsync(EsxiNavigation navigation)
        {
            _logger.Information($"Start gathering data from esxi (Version: {navigation.ServiceContent.about.fullName})");
            _logger.Information($"Retrieving all VMs from ESXi");

            CreateContainerViewResponse viewReference = await navigation.Client.CreateContainerViewAsync(navigation.ServiceContent.viewManager, navigation.ServiceContent.rootFolder, new[] { "VirtualMachine" }, true);

            PropertySpec propertySpec = new PropertySpec
            {
                type = "VirtualMachine",
                pathSet = virtualMachinePorperties
            };

            ObjectSpec objectSpecification = new ObjectSpec
            {
                obj = viewReference.returnval,
                skip = false,
                selectSet = new SelectionSpec[] { new TraversalSpec
                    {
                        name = "viewTraversal",
                        type = "ContainerView",
                        path = "view",
                        skip = false
                    }
                }
            };

            PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec
            {
                propSet = new PropertySpec[]
                {
                    propertySpec
                },
                objectSet = new ObjectSpec[]
                {
                    objectSpecification
                }
            };

            _logger.Information($"Retrieving VM properties from ESXi host at {navigation.ServiceContent.about.instanceUuid}");

            RetrievePropertiesExResponse retrieveResponse = await navigation.Client.RetrievePropertiesExAsync(navigation.ServiceContent.propertyCollector, new PropertyFilterSpec[]
            {
                propertyFilterSpec
            }, new RetrieveOptions());

            _logger.Information($"Retrieved {retrieveResponse.returnval.objects.Length} raw VMs data from ESXi");
            _logger.Information($"Processing VM properties and enrich data");
            
            List<VirtualMachine> Result = new List<VirtualMachine>();

            foreach(ObjectContent singleVirtualMachine in retrieveResponse.returnval.objects)
            {
                Result.Add(new VirtualMachine()
                {
                    Name = (string)singleVirtualMachine.propSet.Where(prop => prop.name.Equals(DefaultValue.EsxiPropertyNameValue)).First().val,
                    Id = (string)singleVirtualMachine.propSet.Where(prop => prop.name.Equals(DefaultValue.EsxiPropertyConfigUuidValue)).First().val,
                    VM = singleVirtualMachine,
                    GuestFileTransfer = new VirtualMachineGuestFileTransfer()
                });

            }

            _logger.Information($"All vms ({Result.Count}) gathered and enriched");

            return Result;
        }

        /// <summary>
        /// This method filter all VMs if there are on and vmware tools are running and match the guest OS filter.
        /// </summary>
        public async Task<List<VirtualMachine>> FilterVMsAsync(EsxiNavigation navigation, List<VirtualMachine> allVMs, GuestOs guestOsFilter, List<string> excludeVmsByName, List<string> includeVmsByName)
        {
            _logger.Information($"Filtering VMs ({allVMs.Count}) based on Guest OS: {guestOsFilter}");
            
            List<VirtualMachine> RawResult = new List<VirtualMachine>();
            
            foreach(VirtualMachine singleVirtualMachine in allVMs)
            {
                string guestOsId = (string)singleVirtualMachine.VM.propSet.Where(prop => prop.name.Equals(DefaultValue.EsxiPropertyConfigGuestIdValue)).First().val;

                if (guestOsId.Contains(guestOsFilter.ToString(), StringComparison.InvariantCultureIgnoreCase))
                {

                    VirtualMachinePowerState runtimePowerState = (VirtualMachinePowerState)singleVirtualMachine.VM.propSet.Where(prop => prop.name.Equals(DefaultValue.EsxiPropertyRuntimePowerStateValue)).First().val;

                    if(runtimePowerState == VirtualMachinePowerState.poweredOn)
                    {
                        string guestToolsRunningState = (string)singleVirtualMachine.VM.propSet.Where(prop => prop.name.Equals(DefaultValue.EsxiPropertyGuestToolsRunningStatusValue)).First().val;

                        if (guestToolsRunningState.Equals(DefaultValue.EsxiPropertyGuestToolsRunningRunStatus))
                        {
                            RawResult.Add(singleVirtualMachine);
                        }
                        else
                        {
                            _logger.Information($"{singleVirtualMachine.Name} skipped due to Guest Tools not running. Detected Guest Tools Running State: {guestToolsRunningState}");
                        }
                    }
                    else
                    {
                        _logger.Information($"{singleVirtualMachine.Name} skipped due to Power State filter. Detected Power State: {runtimePowerState}");
                    }
                }
                else
                {
                    _logger.Information($"{singleVirtualMachine.Name} (GuestID: {singleVirtualMachine.Id}) skipped due to Guest OS filter. Detected Guest OS ID: {guestOsId}");
                }
            }

            List<VirtualMachine> FilteredResult = new List<VirtualMachine>(RawResult);


            foreach (VirtualMachine singleVm in RawResult)
            {
                if (!includeVmsByName.Contains((singleVm.Name)))
                {
                    FilteredResult.Remove(singleVm);
                    _logger.Information($"Removed VM with name {singleVm.Name} because of not being in the include filter");
                }
            }
            
            foreach (string singleVmToExclude in excludeVmsByName)
            {
                int removedCount = FilteredResult.RemoveAll(singleVm => singleVm.Name.Equals(singleVmToExclude));
                if(removedCount > 0)
                {
                    _logger.Information($"Removed {removedCount} VM with name {singleVmToExclude} because of configured exclude filter");
                }
            }
          
            _logger.Information($"Found {FilteredResult.Count} processable vms");

            return FilteredResult;
        }

        //Overwork
        public async Task<VirtualMachine> CopyFileToVMAsync(EsxiNavigation navigation, List<GuestOsLoginInfo> loginInfo, VirtualMachine vm, GuestOs guestOs, FileInfo deploymentFile, HttpClient client)
        {
            vm = await CreateFileUploadUriAsync(navigation, loginInfo, vm, deploymentFile, guestOs);
            
            if(vm.GuestFileTransfer.ApiFileUpload is not null)
            {
                using(FileStream fileStream = new FileStream(deploymentFile.FullName, FileMode.Open, FileAccess.Read))
                {
                    HttpRequestMessage uploadMessage = new HttpRequestMessage()
                    {
                        Method = HttpMethod.Put,
                        RequestUri = vm.GuestFileTransfer.ApiFileUpload,
                        Content = new StreamContent(fileStream)
                        {
                            Headers =
                            {
                                ContentType = new MediaTypeHeaderValue("application/octet-stream"),
                            }
                        }
                    };

                    HttpResponseMessage Response = await client.SendAsync(uploadMessage);

                    if (Response.IsSuccessStatusCode)
                    {
                        _logger.Information($"Fileupload to {vm.Name} on {vm.GuestFileTransfer.GuestFilePath} was succesfull");
                    }
                    else
                    {
                        _logger.Error($"Upload failed with {Response.StatusCode} to {Response.RequestMessage.RequestUri} for {vm.Name} (Is the vm running with working vmware tools?)");
                    }
                }
            }
            else
            {
                _logger.Error($"Cannot upload file to vm {vm.Name} because no upload uri could be created. (Check Username/Password)");
            }

            return vm;
        }

        public async Task<string> CreateTempPathAsync(GuestOs guestOs, FileInfo file)
        {
            switch(guestOs)
            {
                case GuestOs.Windows:
                    string RawPath = Path.Combine(DefaultValue.DefaultWindowsTempPath, Path.GetRandomFileName());
                    RawPath = Path.ChangeExtension(RawPath, file.Extension);
                    return RawPath;
                default:
                    throw new NotImplementedException($"Guest OS {guestOs} not implemented for temp path creation.");
            }
        }

        public async Task<ManagedObjectReference> GetOperationManagerByNameAsync(EsxiNavigation navigation, string managerName)
        {
            _logger.Debug($"Try to get OperationManager with name {managerName}");
            PropertySpec fileManagerPropSpec = new PropertySpec
            {
                type = navigation.ServiceContent.guestOperationsManager.type,
                pathSet = new string[]
                {
                    managerName
                }
            };

            ObjectSpec fileManagerObjSpec = new ObjectSpec
            {
                obj = navigation.ServiceContent.guestOperationsManager,
            };

            PropertyFilterSpec fileManagerfilterSpec = new PropertyFilterSpec
            {
                propSet = new PropertySpec[]
                {
                    fileManagerPropSpec
                },
                objectSet = new ObjectSpec[]
                {
                    fileManagerObjSpec
                }
            };

            ManagedObjectReference propCollectorRef = navigation.ServiceContent.propertyCollector;

            RetrievePropertiesResponse fileManagerPropertyResponse = await navigation.Client.RetrievePropertiesAsync(propCollectorRef, new PropertyFilterSpec[]
            {
                fileManagerfilterSpec
            });

            ManagedObjectReference manager = (ManagedObjectReference)fileManagerPropertyResponse.returnval.First().propSet.First().val;
            return manager;
        }

        public async Task<VirtualMachine> CreateFileUploadUriAsync(EsxiNavigation navigation, List<GuestOsLoginInfo> loginInfo, VirtualMachine vm, FileInfo file, GuestOs guestOs)
        {
            ManagedObjectReference fileManager = await GetOperationManagerByNameAsync(navigation, DefaultValue.EsxiPropertyFileManagerNameValue);

            vm.GuestFileTransfer.GuestFilePath = await CreateTempPathAsync(guestOs, file);
            string uploadUri = null;

            vm = await ValidateLoginAsync(navigation, vm, loginInfo);

            if(vm.LoginInfo is null)
            {
                _logger.Information($"Trying to create file upload uri for vm {vm.Name} with user {vm.LoginInfo.User}");

                NamePasswordAuthentication auth = new NamePasswordAuthentication()
                {
                    username = vm.LoginInfo.User,
                    password = vm.LoginInfo.Password
                };

                try
                {
                    uploadUri = await navigation.Client.InitiateFileTransferToGuestAsync(fileManager, vm.VM.obj, auth, vm.GuestFileTransfer.GuestFilePath, new GuestFileAttributes(), file.Length, false);
                    _logger.Information($"Successfully created file upload uri for vm {vm.Name} with user {vm.LoginInfo.User}");
                }
                catch (FaultException exception)
                {
                    _logger.Error($"Unable to login with user {auth.username} to vm {vm.Name}, try next credential when more are submitted", exception);
                }

                if (uploadUri is not null)
                {
                    vm.GuestFileTransfer.ApiFileUpload = new Uri(uploadUri.Replace("*", navigation.Client.Endpoint.Address.Uri.Host));
                }
            }

            return vm;
        }

        public async Task<VirtualMachine> ValidateLoginAsync(EsxiNavigation navigation, VirtualMachine vm, List<GuestOsLoginInfo> loginInfo)
        {
            ManagedObjectReference authManager = await GetOperationManagerByNameAsync(navigation, DefaultValue.EsxiPropertyAuthManagerNameValue);
            
            _logger.Information($"Start searching valid credentials for vm {vm.Name}");

            foreach(GuestOsLoginInfo singleLoginInfo in loginInfo)
            {
                NamePasswordAuthentication login = new NamePasswordAuthentication()
                {
                    username = singleLoginInfo.User,
                    password = singleLoginInfo.Password
                };

                try
                {
                    await navigation.Client.ValidateCredentialsInGuestAsync(authManager, vm.VM.obj, login);
                    vm.LoginInfo = singleLoginInfo;

                    _logger.Information($"Found working Credential {login.username} on {vm.Name}");
                    
                    break;
                }
                catch(FaultException e)
                {
                    _logger.Warning($"{login.username} doenst worked for {vm.Name}");
                }   
            }

            if (vm.LoginInfo is null)
            {
                _logger.Warning($"No valid credentials found for {vm.Name}");
            }            

            return vm;
        }

        public async Task<VirtualMachine> InstalMsiOnVMAsync(EsxiNavigation navigation, VirtualMachine vm, string installArguments)
        {
            ManagedObjectReference processManager = await GetOperationManagerByNameAsync(navigation, DefaultValue.EsxiPropertyProcessManagerNameValue);

            NamePasswordAuthentication loginInfo = new NamePasswordAuthentication()
            {
                username = vm.LoginInfo.User,
                password = vm.LoginInfo.Password
            };

            GuestProgramSpec startUpInfo = new GuestProgramSpec()
            {
                programPath = DefaultValue.DefaultWindowsMsiExecPath,
                arguments = $"{DefaultValue.DefaultWindowsMsiExecPrefixArguments} \"{vm.GuestFileTransfer.GuestFilePath}\" {installArguments}"
            };

            _logger.Information($"Start {startUpInfo.programPath} {startUpInfo.arguments} on {vm.Name}");

            long processId = await navigation.Client.StartProgramInGuestAsync(processManager, vm.VM.obj, loginInfo, startUpInfo);

            await WaitForProcessToFinishAsync(navigation, vm, processManager, loginInfo, processId);
            
            return vm;
        }

        public async Task WaitForProcessToFinishAsync(EsxiNavigation navigation, VirtualMachine vm, ManagedObjectReference processManager, NamePasswordAuthentication loginInfo, long processId)
        {
            bool ProcIsRunning = true;
            
            long[] SearchPid = new long[]
            {
                processId
            };

            ListProcessesInGuestResponse ProcessResponse;

            _logger.Information($"Start waiting for Process with ID {processId} on {vm.Name}");

            while (ProcIsRunning)
            {
                ProcessResponse = await navigation.Client.ListProcessesInGuestAsync(processManager, vm.VM.obj, loginInfo, SearchPid);

                if (ProcessResponse.returnval[0].endTimeSpecified == true)
                {
                    ProcIsRunning = false;
                    break;
                }
                else
                {
                    await Task.Delay(DefaultValue.DefaultWaitTime);
                }
            }

            _logger.Information($"Process finished {processId} on {vm.Name}");
        }

        public async Task<VirtualMachine> InstallExeOnVMAsync(EsxiNavigation navigation, VirtualMachine vm, string installArgument)
        {
            ManagedObjectReference processManager = await GetOperationManagerByNameAsync(navigation, DefaultValue.EsxiPropertyProcessManagerNameValue);

            NamePasswordAuthentication loginInfo = new NamePasswordAuthentication()
            {
                username = vm.LoginInfo.User,
                password = vm.LoginInfo.Password
            };

            GuestProgramSpec startUpInfo = new GuestProgramSpec()
            {
                programPath = DefaultValue.DefaultWindowsCmdPath,
                arguments = $"{DefaultValue.DefaultWindowsCmdPrefixArguments} \"{vm.GuestFileTransfer.GuestFilePath}\""
            };

            if (!installArgument.Equals(string.Empty))
            {
                startUpInfo.arguments += $" {installArgument}";
            }
            
            _logger.Information($"Start {startUpInfo.programPath} {startUpInfo.arguments} on {vm.Name}");

            long processId = await navigation.Client.StartProgramInGuestAsync(processManager, vm.VM.obj, loginInfo, startUpInfo);

            await WaitForProcessToFinishAsync(navigation, vm, processManager, loginInfo, processId);

            return vm;
        }

        public async Task<VirtualMachine> ExecuteCmdOnVMAsync(EsxiNavigation navigation, VirtualMachine vm, List<GuestOsLoginInfo> guestLoginInfo, string Argument)
        {
            ManagedObjectReference processManager = await GetOperationManagerByNameAsync(navigation, DefaultValue.EsxiPropertyProcessManagerNameValue);
            vm = await ValidateLoginAsync(navigation, vm, guestLoginInfo);
            
            if(vm.LoginInfo is not null)
            {
                NamePasswordAuthentication loginInfo = new NamePasswordAuthentication()
                {
                    username = vm.LoginInfo.User,
                    password = vm.LoginInfo.Password
                };

                GuestProgramSpec startUpInfo = new GuestProgramSpec()
                {
                    programPath = DefaultValue.DefaultWindowsCmdPath,
                    arguments = $"{DefaultValue.DefaultWindowsCmdPrefixArguments} \"{Argument}\""
                };

                _logger.Information($"Start {startUpInfo.programPath} {startUpInfo.arguments} on {vm.Name}");

                long processId = await navigation.Client.StartProgramInGuestAsync(processManager, vm.VM.obj, loginInfo, startUpInfo);

                await WaitForProcessToFinishAsync(navigation, vm, processManager, loginInfo, processId);
            }          

            return vm;
        }
    }
}
