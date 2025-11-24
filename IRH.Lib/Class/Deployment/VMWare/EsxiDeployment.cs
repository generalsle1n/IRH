using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using IRH.Lib.Model.Deployment.Esxi;
using IRH.Lib.VMWare.Eight;
using FileInfo = System.IO.FileInfo;
using System.Net.Http.Headers;

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

            }catch(Exception ex)
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
        public async Task<List<VirtualMachine>> FilterVMsAsync(EsxiNavigation navigation, List<VirtualMachine> allVMs, GuestOs guestOsFilter)
        {
            _logger.Information($"Filtering VMs ({allVMs.Count}) based on Guest OS: {guestOsFilter}");
            
            List<VirtualMachine> Result = new List<VirtualMachine>();
            
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
                            Result.Add(singleVirtualMachine);
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

            _logger.Information($"Found {Result.Count} processable vms");

            return Result;
        }

        //Overwork
        public async Task CopyFileToVMAsync(EsxiNavigation navigation, List<GuestOsLoginInfo> loginInfo, VirtualMachine vm, GuestOs guestOs, FileInfo deploymentFile, HttpClient client)
        {
            vm = await CreateFileUploadUriAsync(navigation,loginInfo,vm,deploymentFile,guestOs);
            
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

        public async Task<VirtualMachine> CreateFileUploadUriAsync(EsxiNavigation navigation, List<GuestOsLoginInfo> loginInfo, VirtualMachine vm, FileInfo file, GuestOs guestOs)
        {
            PropertySpec fileManagerPropSpec = new PropertySpec
            {
                type = navigation.ServiceContent.guestOperationsManager.type,
                pathSet = new string[]
                {
                    DefaultValue.EsxiPropertyFileManagerNameValue
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

            ManagedObjectReference fileManager = (ManagedObjectReference)fileManagerPropertyResponse.returnval.First().propSet.First().val;

            vm.GuestFileTransfer.GuestFilePath = await CreateTempPathAsync(guestOs, file);
            string uploadUri = null;

            foreach (GuestOsLoginInfo singleLoginInfo in loginInfo)
            {
                NamePasswordAuthentication auth = new NamePasswordAuthentication
                {
                    username = singleLoginInfo.User,
                    password = singleLoginInfo.Password
                };

                _logger.Information($"Trying to create file upload uri for vm {vm.Name} with user {auth.username}");

                try
                {
                    uploadUri = await navigation.Client.InitiateFileTransferToGuestAsync(fileManager, vm.VM.obj, auth, vm.GuestFileTransfer.GuestFilePath, new GuestFileAttributes(), file.Length, false);
                    _logger.Information($"Successfully created file upload uri for vm {vm.Name} with user {auth.username}");
                    break;
                }catch(FaultException exception)
                {
                    _logger.Error($"Unable to login with user {auth.username} to vm {vm.Name}, try next credential when more are submitted", exception);
                }
            }

            if(uploadUri is not null)
            {
                vm.GuestFileTransfer.ApiFileUpload = new Uri(uploadUri.Replace("*", navigation.Client.Endpoint.Address.Uri.Host));
            }

            return vm;
        }
    }
}
