using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Messaging.Messages;
using IRH.Ui.Models.Azure;

namespace IRH.Ui.Models.Message.Request;

public class AzureScopeRequestMessage : RequestMessage<ObservableCollection<AzureItemControlTemplate>>{
    
}