using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Messaging;
using IRH.Ui.Lib;
using IRH.Ui.Models.Message.Request;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels.Template;

namespace IRH.Ui.ViewModels.Base;

public abstract partial class AzureViewModelBase<TResultData, TClassType> : ViewModelBase, IRecipient<List<TResultData>>, IRecipient<AzureDataRequestMessage<List<TResultData>>>, IDisposable
{
    protected AzureViewModelBase()
    {
        RegisterRouter();
    }
    
    [ObservableProperty] 
    private ObservableCollection<TResultData> _allItems = new ObservableCollection<TResultData>();
    
    [ObservableProperty] 
    private AzureActionBarViewModel _azureActionBarViewModel = new AzureActionBarViewModel()
    {
        DataType = typeof(List<TResultData>),
        ParentViewModel = typeof(TClassType),
        RequestDataType = typeof(AzureDataRequestMessage<List<TResultData>>)
    };

    internal readonly UiHelper UiHelper = new UiHelper();
    
    protected abstract Task StartAzureProcessAsync(AzureGraphViewModelMessageGeneric<TClassType> message);
    private void RegisterRouter()
    {
        WeakReferenceMessenger.Default.Register<List<TResultData>>(this);
        WeakReferenceMessenger.Default.Register<AzureDataRequestMessage<List<TResultData>>>(this);
        WeakReferenceMessenger.Default.Register<AzureGraphViewModelMessageGeneric<TClassType>>(this, async (sender, data) =>
            {
                await StartAzureProcessAsync(data);
            });
    }

    public void Receive(List<TResultData> message)
    {
        AllItems.Clear();
        foreach (TResultData SingleItem in message)
        {
            AllItems.Add(SingleItem);
        }
    }
    
    public void Receive(AzureDataRequestMessage<List<TResultData>> message)
    {
        message.Reply(AllItems.ToList());
    }

    public void Dispose()
    {
        WeakReferenceMessenger.Default.Unregister<List<TResultData>>(this);
        WeakReferenceMessenger.Default.Unregister<AzureDataRequestMessage<List<TResultData>>>(this);
        WeakReferenceMessenger.Default.Unregister<AzureGraphViewModelMessageGeneric<TClassType>>(this);
    }
}