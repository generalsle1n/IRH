using System;
using Microsoft.Graph;

namespace IRH.Ui.Models.Message.Send;

public class AzureGraphViewModelMessageBase
{
    public required GraphServiceClient Client;
    public required Type Requester;
}