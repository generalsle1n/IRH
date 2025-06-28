using System.Reflection;
using IRH.Lib.Model.Azure.Audit;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Result;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models.Security;
using Microsoft.Kiota.Abstractions;
using Serilog;

namespace IRH.Lib.Class.Azure.Audit;

public class AzureAudit
{
    public AzureAudit(ILogger logger)
    {
        _logger = logger;
    }
    
    private ILogger _logger;
    private const int _timeMultiplyer = 1000;
    public async Task<AuditLogQuery> CreateQuery(GraphServiceClient Client, DateTime Start, DateTime End, string[] Activities, string[] UserLoginFilter = null)
    {
        Guid Id = Guid.NewGuid();

        AuditLogQuery Query = new AuditLogQuery()
        {
            FilterStartDateTime = Start,
            FilterEndDateTime = End,
            OperationFilters = Activities.ToList()
        };

        if (UserLoginFilter is not null)
        {
            Query.UserPrincipalNameFilters = UserLoginFilter.ToList();
        }

        Query.DisplayName = $"Created by IRH_Scanner {Id}";

        string LogText = $"Try to Create an Audit Search with activties {string.Join(", ", Activities)} Id:{Id} and in Timeframe {Start} - {End}";

        if(UserLoginFilter is not null)
        {
            LogText += $" and with Userfilter {string.Join(", ", UserLoginFilter)}";
        }

        _logger.Information(LogText);

        AuditLogQuery Processed = await Client.Security.AuditLog.Queries.PostAsync(Query);
        return Processed;
    }
    
    public async Task<AuditLogQuery> WaitOnQuery(GraphServiceClient Client, AuditLogQuery Query, int WaitTime)
    {
        _logger.Information($"Start for Waiting Query (This can take some minutes, up to 10min): {Query.DisplayName}");

        while (Query.Status == AuditLogQueryStatus.NotStarted || Query.Status == AuditLogQueryStatus.Running)
        {
            _logger.Information($"Query not finished, current State: {Query.Status}");
            await Task.Delay(WaitTime * _timeMultiplyer);
            Query = await Client.Security.AuditLog.Queries[Query.Id].GetAsync(req => req.QueryParameters.Expand = new string[] { "*" });
        }

        _logger.Information($"Query finished: {Query.DisplayName}");
        return Query;
    }
    
    public async Task<AuditLogRecordCollectionResponse> GetResultFromQuery(GraphServiceClient Client, AuditLogQuery Query)
    {
        return await Client.Security.AuditLog.Queries[Query.Id].Records.GetAsync();
    }
    
    public async Task<AuditLogQuery> GetQueryFromName(GraphServiceClient Client, string QueryName)
    {
        AuditLogQueryCollectionResponse Collection = await Client.Security.AuditLog.Queries.GetAsync();

        IEnumerable<AuditLogQuery> Result = Collection.Value.Where(item => item.DisplayName.Contains(QueryName));
        if (Result.Count() >= 1)
        {
            return Result.First();
        }
        else
        {
            return null;
        }
    }
}