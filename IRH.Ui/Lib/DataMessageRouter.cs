using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.Messaging;
using IRH.Lib.Model.Azure.Mail;
using IRH.Ui.Config;

namespace IRH.Ui.Lib;

internal class DataMessageRouter
{
    internal DataMessageRouter()
    {
        RegisterRouter();
    }

    private void RegisterRouter()
    {
        WeakReferenceMessenger.Default.Register<object>(this, (_,data) =>
        {
            Type DataType = data.GetType();

            foreach (string MessageType in DataMessageRouterConfig.Types)
            {
                Type Generic = DataType.GenericTypeArguments[0];
                if (Generic.Name.Equals(MessageType))
                {
                    WeakReferenceMessenger.Default.Send<List<UserMailCollection>>(data as List<UserMailCollection>);
                }
            }
        });
    }
}