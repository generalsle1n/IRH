using Microsoft.Graph.Models;
using Microsoft.Graph.Users.Item.RevokeSignInSessions;

namespace IRH.Commands.Azure.Reporting.Model
{
    public class UserSession
    {
        public User User { get; set; }
        public bool ResetToken {  get; set; }
        public RevokeSignInSessionsPostResponse Response { get; set; }
    }
}
