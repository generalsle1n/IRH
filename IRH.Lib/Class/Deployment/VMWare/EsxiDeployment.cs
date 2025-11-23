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
using IRH.Lib.Model.Azure.Session;
using IRH.Lib.VMWare.Eight;
using Microsoft.Graph.Beta.Groups.Item.Team.Schedule.TimeCards.Item.EndBreak;
using UserSession = IRH.Lib.VMWare.Eight.UserSession;

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
            "name",
            "config.uuid",
            "config.guestFullName",
            "config.guestId",
            "runtime.powerState",
            "guest.toolsRunningStatus",
            "guest.guestFullName",
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

        public async Task<List<ObjectContent>> GetAllVMs(EsxiNavigation navigation)
        {
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

            RetrievePropertiesExResponse retrieveResponse = await navigation.Client.RetrievePropertiesExAsync(navigation.ServiceContent.propertyCollector, new PropertyFilterSpec[]
            {
                propertyFilterSpec
            }, new RetrieveOptions());

            List<ObjectContent> Result = new List<ObjectContent>();

            Result.AddRange(retrieveResponse.returnval.objects);

            return Result;
        }
    }
}
