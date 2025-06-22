using Microsoft.Graph.Models;
using Microsoft.Graph.Users.Item.RevokeSignInSessions;

namespace IRH.Lib.Model.Azure.Session
{
    public class UserSession
    {
        public User User { get; set; }
        public bool ResetToken {  get; set; }
        public RevokeSignInSessionsPostResponse Response { get; set; }
    }
}
