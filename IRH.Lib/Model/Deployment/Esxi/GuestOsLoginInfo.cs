using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class GuestOsLoginInfo
    {
        public required string User { get; set; }
        public required string Password { get; set; }
        public required string Domain { get; set; }
    }
}
