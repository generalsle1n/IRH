using IRH.Lib.Model.Deployment.Esxi;
using IRH.Lib.VMWare.Eight;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Class.Deployment.VMWare
{
    internal class EsxiFactory
    {

        internal EsxiFactory(ILogger logger)
        {
            _logger = logger;
        }

        private readonly ILogger _logger;

        internal async Task<VimPortTypeClient> CreateVimPortTypeClientAsync(HypervisorLoginInfo loginInfo)
        {
            _logger.Debug("Start creating Client type vmware communication");

            Uri hypervisorUri = new Uri($"{loginInfo.Scheme}://{loginInfo.Address}:{loginInfo.Port}/sdk/vimService");
            EndpointAddress hypervisorAdress = new EndpointAddress(hypervisorUri);

            BasicHttpsBinding DefaultBinding = new BasicHttpsBinding();
            CustomBinding CustomBinding = new CustomBinding(DefaultBinding);

            VimPortTypeClient Client = new VimPortTypeClient(CustomBinding, hypervisorAdress);

            HttpClientHandler httpClientHandler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                {
                    return true;
                }
            };

            VMwareHttpMessageHandlerBehavior vmwareHttpMessageHandlerBehavior = new VMwareHttpMessageHandlerBehavior(httpClientHandler);
            Client.Endpoint.EndpointBehaviors.Add(vmwareHttpMessageHandlerBehavior);

            _logger.Debug("Finished creating api client");

            return Client;
        }
    }
}
