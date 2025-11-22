using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IRH.Lib.VMWare.Eight;

namespace IRH.Lib.Model.Deployment.Esxi
{
    public class EsxiNavigation
    {
        public VimPortTypeClient Client { get; set; }
        public UserSession UserSession { get; set; }
        public ServiceContent ServiceContent { get; set; }
    }
}
