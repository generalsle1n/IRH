using Microsoft.Graph.Models;

namespace IRH.Lib.Model.Azure.Auth;

public class ApplicationLogin
{
    public string Id { get; set; }
    public PasswordCredential Credential { get; set; }
    public Application RawApplication { get; set; }
    public string TenantId { get; set; }
}