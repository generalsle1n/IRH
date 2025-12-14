using IRH.Lib.VMWare.Eight;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class VirtualMachineNetwork
    {
        public ManagedObjectReference DestinationNetwork { get; set; }
        public List<VirtualMachineNetworkAdapter> Adapter { get; set; } = new List<VirtualMachineNetworkAdapter>();
    }
}
