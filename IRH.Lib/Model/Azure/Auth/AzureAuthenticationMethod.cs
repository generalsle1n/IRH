using Microsoft.Graph.Models;

namespace IRH.Lib.Model.Azure.Auth;

public class AzureAuthenticationMethod
{
    public List<AzureMethodProperty> MethodProperties { get; set; }
    public AuthenticationMethod Method { get; set; }
}