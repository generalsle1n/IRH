using IRH.Lib.Model.General;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class HypervisorLoginInfo
    {
        public required string Address { get; set; }
        public required int Port { get; set; }
        public required WebScheme Scheme { get; set; }
        public required string User { get; set; }
        public required string Password { get; set; }
    }
}
