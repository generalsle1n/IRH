using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class VirtualMachineGuestFileTransfer
    {
        public Uri ApiFileUpload { get; set; }
        public string GuestFilePath { get; set; }
    }
}
