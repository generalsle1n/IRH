using Microsoft.Graph.Models;

namespace IRH.Commands.Azure.Reporting.Model
{
    public class UserMFA
    {
        public User User { get; set; }
        public List<AuthenticationMethod> MFA { get; set; }
        public int AllMFACount {  get; set; }
    }
}
