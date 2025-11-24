using IRH.Lib.VMWare.Eight;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class VirtualMachine
    {
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required ObjectContent VM { get; set; }
        public required VirtualMachineGuestFileTransfer GuestFileTransfer { get; set; }
        public GuestOsLoginInfo LoginInfo { get; set; }
    }
}
