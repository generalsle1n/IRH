using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog.Core;

namespace IRH.Commands.Azure.Helper
{
    internal class UserHelper
    {
        internal UserHelper(Logger logger)
        {
            _logger = logger;
        }

        private readonly Logger _logger;

        internal async Task<UserCollectionResponse> GetUsersAsync(GraphServiceClient Client, string[] GroupIDs)
        {
            _logger.Information("Querying all Users with MemberOf Attribute, this can take some time");
            UserCollectionResponse AllUsers = await Client.Users.GetAsync((search) =>
            {
                search.QueryParameters.Expand = new string[] { "memberOf" };
            });

            if (GroupIDs.Length > 0)
            {
                _logger.Information("Start on filtering User");
                int Count = 1;

                UserCollectionResponse CleanUser = new UserCollectionResponse();
                CleanUser.Value = new List<User>();
                foreach (User SingleUser in AllUsers.Value)
                {
                    foreach (DirectoryObject SingleGroup in SingleUser.MemberOf)
                    {
                        bool Result = GroupIDs.Contains(SingleGroup.Id);
                        if (Result)
                        {
                            CleanUser.Value.Add(SingleUser);
                            break;
                        }
                    }

                    _logger.Information($"Processed {Count} from {AllUsers.Value.Count}");
                    Count++;
                }

                _logger.Information($"The specified filter returned {CleanUser.Value.Count} from {AllUsers.Value.Count} Users");

                return CleanUser;
            }
            else
            {
                _logger.Information($"Found {AllUsers.Value.Count} Users without Filtering");
                return AllUsers;
            }
        }
    }
}
