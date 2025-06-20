using IRH.Lib.Model.Azure.Auth;
using Microsoft.Graph.Models;

namespace IRH.Lib.Model.Azure.Result
{
    public class UserMFA
    {
        public User User { get; set; }
        public List<AzureAuthenticationMethod> MFA { get; set; }
        public int AllMFACount {  get; set; }
    }
}
