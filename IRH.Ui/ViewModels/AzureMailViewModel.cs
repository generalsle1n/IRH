using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using IRH.Lib;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.Mail;
using IRH.Lib.Model.Azure.Mail;
using IRH.Ui.Lib;
using IRH.Ui.Models.Message.Request;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels.Template;
using Microsoft.Graph.Models;
using Serilog;

namespace IRH.Ui.ViewModels;

public partial class AzureMailViewModel : ViewModelBase, IRecipient<List<UserMailCollection>>, IRecipient<AzureDataRequestMessage<List<UserMailCollection>>>
{
    public AzureMailViewModel()
    {
        WeakReferenceMessenger.Default.Register<AzureDataRequestMessage<List<UserMailCollection>>>(this);
        WeakReferenceMessenger.Default.Register<List<UserMailCollection>>(this);
        WeakReferenceMessenger.Default.Register<AzureGraphViewModelMessageGeneric<AzureMailViewModel>>(this, async (sender, data) =>
            {
                await StartAzureProcess(data);
            });
    }
    
    [ObservableProperty]
    private ObservableCollection<UserMailCollection> _allMails = new ObservableCollection<UserMailCollection>();
   
    [ObservableProperty] 
    private AzureActionBarViewModel _azureActionBarViewModel = new AzureActionBarViewModel()
    {
        DataType = typeof(List<UserMailCollection>),
        ParentViewModel = typeof(AzureMailViewModel),
        RequestDataType = typeof(AzureDataRequestMessage<List<UserMailCollection>>),
        ShouldElevateToAppAccess = true
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
    private AzureSubjectViewModel _azureSubjectViewModel = new AzureSubjectViewModel();
    
    [ObservableProperty]
    private AzureDeleteItemViewModel _azureDeleteItemViewModel = new AzureDeleteItemViewModel();
    
    private readonly UiHelper _uiHelper = new UiHelper();
    
    private async Task StartAzureProcess(AzureGraphViewModelMessageGeneric<AzureMailViewModel> message)
    {
        string[] AllGroups = _uiHelper.GetContentFromObservableCollection(AzureGroupViewModel.AllGroupFilter, removeEmpty: true);
        string[] SubjectFilter = _uiHelper.GetContentFromObservableCollection(AzureSubjectViewModel.AllSubjectFilter, removeEmpty: true);

        DateTime StartDateFilter = await AzureDateViewModel.CalculateStartDateAsync();
        DateTime EndDateFilter = await AzureDateViewModel.CalculateEndDateAsync();
        
        AzureUser AzureUser = new AzureUser(Log.Logger);
        UserCollectionResponse Users = await AzureUser.GetUsersAsync(message.Client, AllGroups);
        
        AzureMail AzureMail = new AzureMail(Log.Logger);
        List<UserMailCollection> UserMailCollection = await AzureMail.GetMails(message.Client, Users,SubjectFilter, StartDateFilter, EndDateFilter);
        
        AllMails.Clear();
        foreach (UserMailCollection SingleMail in UserMailCollection)
        {
            AllMails.Add(SingleMail);
        }

        if (AzureDeleteItemViewModel.ItemDeleteActive)
        {
            foreach (UserMailCollection SingleMail in AllMails)
            {
                await AzureMail.DeleteMails(message.Client, SingleMail);
                SingleMail.Deleted = true;
            }
        }
        
        AzureActionBarViewModel.LoadingRingEnabled = false;
        AzureActionBarViewModel.UserCode = String.Empty;
        AzureActionBarViewModel.ExportEnabled = true;
    }

    public void Receive(List<UserMailCollection> message)
    {
        AllMails.Clear();
        foreach (UserMailCollection SingleMail in message)
        {
            AllMails.Add(SingleMail);
        }
    }
    
    public void Receive(AzureDataRequestMessage<List<UserMailCollection>> message)
    {
        message.Reply(AllMails.ToList());
    }
    
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
}