using IRH.Lib.Model.Azure.Result;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Class.Azure.MFA
{
    public class AzureMFA
    {
        public async Task<List<UserMFA>> GetAllUsersMFA(GraphServiceClient Client, UserCollectionResponse AllUsers, Logger logger = null)
        {
            List<UserMFA> Result = new List<UserMFA>();
            
            if(logger is not null)
            {
                logger.Information($"Start getting MFA Methods for {AllUsers.Value.Count} Users");
            }

            int Count = 1;

            foreach (User SingleUser in AllUsers.Value)
            {
                AuthenticationMethodCollectionResponse AuthMethods = await Client.Users[SingleUser.Id].Authentication.Methods.GetAsync();

                UserMFA SingleUserResult = new UserMFA()
                {
                    User = SingleUser,
                    MFA = new List<AuthenticationMethod>(),
                    AllMFACount = AuthMethods.Value.Count
                };

                SingleUserResult.MFA.AddRange(AuthMethods.Value);

                Result.Add(SingleUserResult);

                if(logger is not null)
                {
                    logger.Information($"Process MFA {Count} from {AllUsers.Value.Count}");
                }

                Count++;
            }

            return Result;
        }

    }
}
