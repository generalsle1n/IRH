using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class VirtualMachineNetworkAdapter
    {
        public required string MacAddress { get; set; }
        public required string OrginalNetwork { get; set; }
        public required string DestinatioNetwork { get; set; }
    }
}
