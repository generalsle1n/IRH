using IRH.Lib.Model.Azure.Result;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using IRH.Lib.Model.Azure.Auth;

namespace IRH.Lib.Class.Azure.MFA
{
    public class AzureMFA
    {
        public AzureMFA(ILogger logger)
        {
            _logger = logger;
        }

        private readonly ILogger _logger;

        public async Task<List<UserMFA>> GetAllUsersMFA(GraphServiceClient Client, UserCollectionResponse AllUsers, CancellationToken singleCancellationToken = new CancellationToken())
        {
            List<UserMFA> Result = new List<UserMFA>();
            _logger.Information($"Start getting MFA Methods for {AllUsers.Value.Count} Users");

            int Count = 1;

            foreach (User SingleUser in AllUsers.Value)
            {
                AuthenticationMethodCollectionResponse AuthMethods = await Client.Users[SingleUser.Id].Authentication.Methods.GetAsync(cancellationToken: singleCancellationToken);

                UserMFA SingleUserResult = new UserMFA()
                {
                    User = SingleUser,
                    MFA = new List<AuthenticationMethod>(),
                    AllMFACount = AuthMethods.Value.Count
                };

                foreach (AuthenticationMethod SingleAuthMethod in AuthMethods.Value)
                {
                    SingleUserResult.MFA.Add(new AzureAuthenticationMethod()
                    {
                        Method = SingleAuthMethod,
                        MethodProperties = await GetPropertiesFromAutheticationMethod(SingleAuthMethod)
                    });
                }

                Result.Add(SingleUserResult);
                _logger.Information($"Process MFA {Count} from {AllUsers.Value.Count}");

                Count++;
            }

            return Result;
        }

        public async Task<List<AzureAuthenticationMethodProperty>> GetPropertiesFromAutheticationMethod(AuthenticationMethod Method)
        {
            List<AzureAuthenticationMethodProperty> Result = new List<AzureAuthenticationMethodProperty>();
            
            PropertyInfo[] AllProperties = Method.GetType().GetProperties();
            IEnumerable<PropertyInfo> AllStringVal = AllProperties.Where(prop => prop.PropertyType.Name.Equals("String"));

            foreach (PropertyInfo Property in AllProperties)
            {
                AzureAuthenticationMethodProperty SingleProperty = new AzureAuthenticationMethodProperty()
                {
                    PropertyName = Property.Name,
                    PropertyValue = Property.GetValue(Method),
                    IsStringProperty = false,
                    PropertyTypeName = Property.PropertyType.FullName,
                };

                if (Property.PropertyType.Name.Equals("String"))
                {
                    SingleProperty.IsStringProperty = true;
                }
                
                Result.Add(SingleProperty);
            }
            
            return Result;
        }
        
    }
}
