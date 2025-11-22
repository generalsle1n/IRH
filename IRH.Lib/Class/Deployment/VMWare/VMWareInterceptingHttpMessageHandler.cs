using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Class.Deployment.VMWare
{
    internal class VMWareInterceptingHttpMessageHandler : DelegatingHandler
    {
        internal VMWareInterceptingHttpMessageHandler(HttpMessageHandler innerHandler, VMwareHttpMessageHandlerBehavior parent)
        {
            InnerHandler = innerHandler;
            _parentHandler = parent;
        }

        private readonly VMwareHttpMessageHandlerBehavior _parentHandler;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_parentHandler.OnSending is not null)
            {
                HttpResponseMessage shortCircuitResponse = _parentHandler.OnSending(request, cancellationToken);
                if (shortCircuitResponse is not null)
                {
                    return shortCircuitResponse;
                }
            }

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (_parentHandler.OnSent is not null)
            {
                return _parentHandler.OnSent(response, cancellationToken);
            }

            return response;
        }
    }
}
