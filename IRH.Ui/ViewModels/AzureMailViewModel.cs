using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using CommunityToolkit.Mvvm.Messaging.Messages;
using IRH.Lib;
using IRH.Lib.Model.Azure.Mail;
using IRH.Ui.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels.Template;

namespace IRH.Ui.ViewModels;

public partial class AzureMailViewModel : ViewModelBase, IRecipient<List<UserMailCollection>>, IRecipient<AzureGraphViewModelMessageGeneric<AzureMailViewModel>>
{
    public AzureMailViewModel()
    {
        WeakReferenceMessenger.Default.Register<List<UserMailCollection>>(this);
        WeakReferenceMessenger.Default.Register<AzureGraphViewModelMessageGeneric<AzureMailViewModel>>(this);
    }
    
    [ObservableProperty]
    private ObservableCollection<UserMailCollection> _allMails = new ObservableCollection<UserMailCollection>();
   
    [ObservableProperty] 
    private AzureActionBarViewModel _azureActionBarViewModel = new AzureActionBarViewModel()
    {
        DataType = typeof(List<UserMailCollection>),
        ParentViewModel = typeof(AzureMailViewModel)
    };
    
    [ObservableProperty]
    private AzureGroupViewModel _azureGroupViewModel = new AzureGroupViewModel();
    
    [ObservableProperty]
    private AzureDateViewModel _azureDateViewModel = new AzureDateViewModel();
    
    [ObservableProperty]
    private AzureScopeViewModel _azureScopeViewModel = new AzureScopeViewModel()
    {
        AllScopes = UiHelper.CreateObservableItemControlTemplateFromList(DefaultValue.AzureMailCleanupPermissions)
    };
    
    [ObservableProperty]
    private AzureActionViewModel _azureActionViewModel = new AzureActionViewModel()
    {
        AllActions = new ObservableCollection<string>()
        {
            Resources.Strings.Azure_Mail_Action_Preview_Text,
            Resources.Strings.Azure_Mail_Action_Delete_Text
        }
    };
    
    private UiHelper _uiHelper = new UiHelper();
    
    [RelayCommand]
    private async Task OpenMailAsync(MailStatus mailStatus, CancellationToken token)
    {
        string TempFile = Path.GetTempFileName();
        string HtmlTempFile = Path.ChangeExtension(TempFile, ".html");
        
        File.Move(TempFile, HtmlTempFile);

        using (FileStream Stream = new FileStream(HtmlTempFile, FileMode.Open, FileAccess.ReadWrite))
        using (StreamWriter Writer = new StreamWriter(Stream))    
        {
            await Writer.WriteAsync(mailStatus.Mail.Body.Content);
        }

        await _uiHelper.OpenUrlInBrowserAsync(new Uri(HtmlTempFile));
    }
    
    public void Receive(List<UserMailCollection> message)
    {
        AllMails.Clear();
        foreach (UserMailCollection SingleMail in message)
        {
            AllMails.Add(SingleMail);
        }
    }

    public void Receive(AzureGraphViewModelMessageGeneric<AzureMailViewModel> message)
    {
        Console.WriteLine();
        throw new NotImplementedException();
    }
}