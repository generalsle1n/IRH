using Microsoft.Graph.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;

namespace IRH.Lib.Model.Azure.Mail
{
    public partial class UserMailCollection : ObservableObject
    {
        public User User { get; set; }
        public MailStatus MailStatus { get; set; }
        
        [ObservableProperty] 
        private bool _deleted = false;

    }
}
