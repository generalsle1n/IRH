using IRH.Lib.Model.Azure.Session;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Users.Item.RevokeSignInSessions;
using Serilog;

namespace IRH.Lib.Class.Azure.Session;

public class AzureSession
{
    public AzureSession(ILogger logger)
    {
        _logger = logger;
    }

    private readonly ILogger _logger;
    
    public async Task<List<UserSession>> ResetUserSessionsAsync(GraphServiceClient Client, UserCollectionResponse AllUsers)
    {
        List<UserSession> Result = new List<UserSession>();
        _logger.Information($"Start reseting RefreshToken for {AllUsers.Value.Count} Users");

        int Count = 1;

        foreach (User SingleUser in AllUsers.Value)
        {

            RevokeSignInSessionsPostResponse SingleUserResetResult = await Client.Users[SingleUser.Id].RevokeSignInSessions.PostAsRevokeSignInSessionsPostResponseAsync();

            UserSession SingleUserResult = new UserSession()
            {
                User = SingleUser,
                ResetToken = SingleUserResetResult.Value.Value,
                Response = SingleUserResetResult
            };

            Result.Add(SingleUserResult);
            _logger.Information($"Process Revokation {Count} from {AllUsers.Value.Count}");
            Count++;
        }

        return Result;
    }

    public async Task<UserSession> ResetSingleUserSessionAsync(GraphServiceClient Client, UserSession SingleUser)
    {
        RevokeSignInSessionsPostResponse SingleUserResetResult = await Client.Users[SingleUser.User.Id].RevokeSignInSessions.PostAsRevokeSignInSessionsPostResponseAsync();

        SingleUser.Response = SingleUserResetResult;
        SingleUser.ResetToken = SingleUserResetResult.Value.Value;
        
        return SingleUser;
    }
}