using IRH.Lib.Model.Azure.Mail;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog;
using System.Text;
using Microsoft.Graph.Models.ODataErrors;

namespace IRH.Lib.Class.Azure.Mail
{
    public class AzureMail
    {
        public AzureMail(ILogger logger)
        {
            _logger = logger;
        }

        private readonly ILogger _logger;

        public async Task<List<UserMailCollection>> GetMails(GraphServiceClient Client, UserCollectionResponse UserCollection, string[] SubjectFilter, DateTime StartFilter, DateTime EndFilter)
        {
            //Todo: schauen wo ich ggfs getvalue anstelle von getrequiredvalue machen soll
            List<UserMailCollection> Result = new List<UserMailCollection>();

            int Count = 1;

            foreach (User SingleUser in UserCollection.Value)
            {
                _logger.Information($"Processing User {Count} from {UserCollection.Value.Count}");
                bool UserHasMailbox = await CheckIfMailboxExists(Client, SingleUser);

                if (UserHasMailbox)
                {
                    MessageCollectionResponse MailResult = await Client.Users[SingleUser.Id].Messages.GetAsync((filter) =>
                    {
                        filter.QueryParameters.Filter = CreateGraphFilter(SubjectFilter, StartFilter, EndFilter);
                    });

                    PageIterator<Message, MessageCollectionResponse> Iterator = PageIterator<Message, MessageCollectionResponse>.CreatePageIterator(Client, MailResult, (singleMail) =>
                    {
                        if (!MailResult.Value.Contains(singleMail))
                        {
                            MailResult.Value.Add(singleMail);
                        }

                        return true;
                    });

                    await Iterator.IterateAsync();

                    _logger.Information($"Gatherd Mail data for User {Count}");

                    UserMailCollection Collection = new UserMailCollection()
                    {
                        User = SingleUser,
                        Mails = new List<MailStatus>()
                    };

                    foreach(Message SingleMessage in MailResult.Value)
                    {
                        Collection.Mails.Add(new MailStatus()
                        {
                            Mail = SingleMessage,
                            Deleted = false
                        });
                    }

                    Result.Add(Collection);
                }
                
                Count++;
            }
            
            return Result;
        }
        public async Task DeleteMails(GraphServiceClient Client, List<UserMailCollection> UserMailCollection)
        {
            foreach(UserMailCollection Collection in UserMailCollection)
            {
                _logger.Information($"Processing User {Collection.User.UserPrincipalName} with {Collection.Mails.Count} mails to delete");
                int Count = 1;
                
                foreach (MailStatus SingleMailStatus in Collection.Mails)
                {
                    await Client.Users[Collection.User.Id].Messages[SingleMailStatus.Mail.Id].DeleteAsync();
                    _logger.Information($"Deleted Mail {Count} from {Collection.Mails.Count} for User {Collection.User.UserPrincipalName}");
                    Count++;
                }
            }
        public async Task DeleteMails(GraphServiceClient Client, UserMailCollection UserMailCollection)
        {
            _logger.Information($"Processing User {UserMailCollection.User.UserPrincipalName}");
            
            await Client.Users[UserMailCollection.User.Id].Messages[UserMailCollection.MailStatus.Mail.Id].PermanentDelete.PostAsync();
            
            _logger.Information($"Deleted Mail {UserMailCollection.MailStatus.Mail.Subject} fromfor User {UserMailCollection.User.UserPrincipalName}");
        }
        private string CreateGraphFilter(string[] SubjectFilter, DateTime StartFilter, DateTime EndFilter)
        {
            string StartDateFilter = $"ReceivedDateTime ge {StartFilter.ToString(DefaultValue.DefaultDateFormat)}";
            string EndDateFilter = $"ReceivedDateTime le {EndFilter.ToString(DefaultValue.DefaultDateFormat)}";

            string GraphFilter = $"{StartDateFilter} and {EndDateFilter}";

            if (SubjectFilter.Length > 0)
            {
                StringBuilder SubjectFilterBuilder = new StringBuilder();
                SubjectFilterBuilder.Append(" and (");
                foreach (string SingleSubject in SubjectFilter)
                {
                    SubjectFilterBuilder.Append($"contains(subject, '{SingleSubject}')");
                    SubjectFilterBuilder.Append(" or ");
                }
                SubjectFilterBuilder.Remove(SubjectFilterBuilder.Length - 4, 4);
                SubjectFilterBuilder.Append(")");
                GraphFilter += SubjectFilterBuilder.ToString();
            }

            return GraphFilter;
        }
        private async Task<bool> CheckIfMailboxExists(GraphServiceClient Client, User SingleUser)
        {
            bool MailboxExists = true;
            
            try
            {
                MailboxSettings Settings = await Client.Users[SingleUser.Id].MailboxSettings.GetAsync();
            }
            catch (ODataError ex)
            {
                MailboxExists = false;
                _logger.Information($"No Mailbox for User {SingleUser.UserPrincipalName}");
            }
            
            return MailboxExists;
        }
    }
}
