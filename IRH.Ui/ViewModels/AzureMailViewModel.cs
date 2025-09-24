using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using IRH.Lib;
using IRH.Lib.Model.Azure.Mail;
using IRH.Ui.Lib;
using IRH.Ui.ViewModels.Template;

namespace IRH.Ui.ViewModels;

public partial class AzureMailViewModel : ViewModelBase, IRecipient<List<UserMailCollection>>
{
    public AzureMailViewModel()
    {
        WeakReferenceMessenger.Default.Register(this);
    }
    public ObservableCollection<UserMailCollection> AllMails { get; set; } = new ObservableCollection<UserMailCollection>();
   
    [ObservableProperty] 
    private AzureActionBarViewModel _azureActionBarViewModel = new AzureActionBarViewModel()
    {
        DataType = (new List<UserMailCollection>()).GetType()
    };
    
    [ObservableProperty]
    private AzureGroupViewModel _azureGroupViewModel = new AzureGroupViewModel();
    
    [ObservableProperty]
    private AzureDateViewModel _azureDateViewModel = new AzureDateViewModel();
    
    [ObservableProperty]
    private AzureScopeViewModel _azureScopeViewModel = new AzureScopeViewModel()
    {
        AllScopes = UIHelper.CreateObservableItemControlTemplateFromList(DefaultValue.AzureMailCleanupPermissions)
    };
    
    public void Receive(List<UserMailCollection> message)
    {
        AllMails.Clear();
        foreach (UserMailCollection SingleMail in message)
        {
            AllMails.Add(SingleMail);
        }
    }
}