using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Graph.Models;
using Microsoft.Graph.Users.Item.RevokeSignInSessions;

namespace IRH.Lib.Model.Azure.Session
{
    public partial class UserSession : ObservableObject
    {
        public User User { get; set; }

        [ObservableProperty] 
        private bool _resetToken;
        public RevokeSignInSessionsPostResponse Response { get; set; }
    }
}
