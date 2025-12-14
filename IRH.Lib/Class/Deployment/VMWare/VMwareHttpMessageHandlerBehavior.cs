using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Class.Deployment.VMWare
{
    internal class VMwareHttpMessageHandlerBehavior : IEndpointBehavior
    {
        

        internal VMwareHttpMessageHandlerBehavior(HttpClientHandler customHandler)
        {
            httpHandler = customHandler;
        }
        
        private readonly HttpClientHandler httpHandler;
        
        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
        {         
            Func<HttpClientHandler, HttpMessageHandler> bindingHandlerFunction = new Func<HttpClientHandler, HttpMessageHandler>((handler) =>
            {
                return new VMWareInterceptingHttpMessageHandler(httpHandler, this);
            });

            bindingParameters.Add(bindingHandlerFunction);
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {

        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
        {

        }

        public void Validate(ServiceEndpoint endpoint)
        {

        }

        public Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> OnSending { get; set; }
        public Func<HttpResponseMessage, CancellationToken, HttpResponseMessage> OnSent { get; set; }

    }
}
