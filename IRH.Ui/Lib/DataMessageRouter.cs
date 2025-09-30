using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.Messaging;
using IRH.Lib.Model.Azure.Mail;
using IRH.Ui.Config;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels;

namespace IRH.Ui.Lib;

internal class DataMessageRouter : IRecipient<AzureGraphViewModelMessageBase>
{
    internal DataMessageRouter()
    {
        WeakReferenceMessenger.Default.Register<AzureGraphViewModelMessageBase>(this);
        RegisterRouter();
    }

    private void RegisterRouter()
    {
        WeakReferenceMessenger.Default.Register<object>(this, (_,data) =>
        {
            Type DataType = data.GetType();
            
            //https://learn.microsoft.com/de-de/dotnet/communitytoolkit/diagnostics/guard
            //IsAssignable to
            
            foreach (string MessageType in DataMessageRouterConfig.Types)
            {
                Type Generic = DataType.GenericTypeArguments[0];
                if (Generic.Name.Equals(MessageType))
                {
                    WeakReferenceMessenger.Default.Send((data as List<UserMailCollection>)!);
                }
            }
        });
    }

    private AzureGraphViewModelMessageGeneric<T> CreateAzureGraphViewModelMessageGeneric<T>(AzureGraphViewModelMessageBase message)
    {
        Type BaseType = typeof(AzureGraphViewModelMessageGeneric<>);
        Type GenericType = GenericType = BaseType.MakeGenericType(message.Requester);
        AzureGraphViewModelMessageGeneric<T> SendMessage = Activator.CreateInstance(GenericType) as AzureGraphViewModelMessageGeneric<T>;
            
            SendMessage.Client = message.Client;
            SendMessage.Requester = message.Requester;
            
        SendMessage.Client = message.Client;
        SendMessage.Requester = message.Requester;
        
        return SendMessage;
    }
            WeakReferenceMessenger.Default.Send(SendMessage);
        }
    }
}