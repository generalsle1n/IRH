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

        public async Task DeploySetupToSingleMachineAsync(HypervisorLoginInfo hypervisorLoginInfo)
        {
            
        }

        public async Task<EsxiNavigation> LoginAsync(HypervisorLoginInfo loginInfo)
        {
            _logger.Information($"Try to connect to {loginInfo.Scheme}://{loginInfo.Address}:{loginInfo.Port} with user {loginInfo.User}");
            VimPortTypeClient client = await _esxiFactory.CreateVimPortTypeClientAsync(loginInfo);

            EsxiNavigation Result = new EsxiNavigation()
            {
                Client = client,
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
        public async Task CopyFileToAllVMsAsync(EsxiNavigation navigation, GuestOsLoginInfo loginInfo, List<VirtualMachine> vms, FileInfo deploymentFile)
        {
            await CreateFileUploadUri(navigation, loginInfo, vms.First());
            

            //string uploadUrl = await navigation.Client.InitiateFileTransferToGuestAsync(fileMgrMor, vms.First().VM.obj, auth, @"C:\lol.dll", new GuestFileAttributes(), deploymentFile.Length, true);
            string uploadUrl = "https://*/folder/lol.dll?dcPath=ha-datacenter&dsName=datastore1&vmPathName=lol.dll";
            uploadUrl = uploadUrl.Replace("*", "192.168.64.128");

            Console.WriteLine();
            byte[] fileBytes = File.ReadAllBytes(deploymentFile.FullName);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uploadUrl);
            request.Method = "PUT";
            request.ContentLength = fileBytes.Length;
            request.ContentType = "application/octet-stream";

            // Optional, falls selbstsigniertes Zertifikat auf vCenter/ESXi:
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            // Datei schreiben
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(fileBytes, 0, fileBytes.Length);
            }

            // Antwort abrufen und prüfen
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                {
                    Console.WriteLine("Datei erfolgreich hochgeladen!");
                }
                else
                {
                    Console.WriteLine($"Fehler beim Upload: {response.StatusCode} {response.StatusDescription}");
                }
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();



        }

        public async Task<VirtualMachine> CreateFileUploadUri(EsxiNavigation navigation, GuestOsLoginInfo loginInfo, VirtualMachine vm, FileInfo file)
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

            switch(gues)
            
            NamePasswordAuthentication auth = new NamePasswordAuthentication
            {
                username = loginInfo.User,
                password = loginInfo.Password
            };



            await navigation.Client.InitiateFileTransferToGuestAsync(fileManager, vm.VM.obj, auth, vm.GuestFileTransfer.GuestFilePath, new GuestFileAttributes(), file.Length, true);

            return "";
        }
    }
}
