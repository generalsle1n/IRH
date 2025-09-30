using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.Mail;
using IRH.Lib.Model.Azure.Mail;
using IRH.Ui.Lib;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels.Template;
using Microsoft.Graph.Models;
using Serilog;

namespace IRH.Ui.ViewModels;

public partial class AzureMailViewModel : AzureViewModelBase<UserMailCollection, AzureMailViewModel>
{
    public AzureMailViewModel()
    {
        AzureActionBarViewModel.ShouldElevateToAppAccess = true;
    }
    
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
    
        await UiHelper.OpenUrlInBrowserAsync(new Uri(HtmlTempFile));
    }
    protected override async Task StartAzureProcessAsync(AzureGraphViewModelMessageGeneric<AzureMailViewModel> message)
    {
        string[] AllGroups = UiHelper.GetContentFromObservableCollection(AzureGroupViewModel.AllGroupFilter, removeEmpty: true);
        string[] SubjectFilter = UiHelper.GetContentFromObservableCollection(AzureSubjectViewModel.AllSubjectFilter, removeEmpty: true);
        
        DateTime StartDateFilter = await AzureDateViewModel.CalculateStartDateAsync();
        DateTime EndDateFilter = await AzureDateViewModel.CalculateEndDateAsync();
        
        AzureUser AzureUser = new AzureUser(Log.Logger);
        UserCollectionResponse Users = await AzureUser.GetUsersAsync(message.Client, AllGroups);
        
        AzureMail AzureMail = new AzureMail(Log.Logger);
        List<UserMailCollection> UserMailCollection = await AzureMail.GetMails(message.Client, Users,SubjectFilter, StartDateFilter, EndDateFilter);
        
        AllItems.Clear();
        foreach (UserMailCollection SingleMail in UserMailCollection)
        {
            AllItems.Add(SingleMail);
        }
        
        if (AzureDeleteItemViewModel.ItemDeleteActive)
        {
            foreach (UserMailCollection SingleMail in AllItems)
            {
                await AzureMail.DeleteMails(message.Client, SingleMail);
                SingleMail.Deleted = true;
            }
        }
        
        AzureActionBarViewModel.SetUiToProcessFinishMode();
    }
}