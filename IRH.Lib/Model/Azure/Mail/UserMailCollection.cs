using Microsoft.Graph.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Model.Azure.Mail
{
    public class UserMailCollection
    {
        public User User { get; set; }
        public MailStatus MailStatus { get; set; }
        public bool Deleted { get; set; }
        
    }
}
