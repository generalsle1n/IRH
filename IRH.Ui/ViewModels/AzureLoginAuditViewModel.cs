using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.SimplePreferences;
using Azure.Identity;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Class.Azure.Audit;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Session;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Azure.Result;
using IRH.Lib.Model.Azure.Session;
using IRH.Ui.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.Resources;
using Microsoft.Graph.Beta;
using Microsoft.Graph.Beta.Models.Security;
using Serilog;

namespace IRH.Ui.ViewModels;

public partial class AzureLoginAuditViewModel : ViewModelBase
{
    private UIHelper _uiHelper = new UIHelper();
    [ObservableProperty] 
    private string _userCode;
    [ObservableProperty] 
    private bool _copyUserCodeEnabled = false;
    [ObservableProperty] 
    private bool _openBrowserEnabled = false;
    [ObservableProperty] 
    private bool _loadingRingEnabled = false;
    [ObservableProperty] 
    private bool _exportEnabled = false;
    [ObservableProperty]
    private ReportPrintLevel _selectedReportLevel = DefaultValue.PrintLevel;
    [ObservableProperty]
    DateTime _selectedStartDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
    [ObservableProperty]
    DateTime _selectedEndDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
    [ObservableProperty]
    TimeSpan _selectedStartTime = new TimeSpan(0, 0, 0);
    [ObservableProperty]
    TimeSpan _selectedEndTime = new TimeSpan(23, 59, 59);
    [ObservableProperty]
    string _existingQueryID = string.Empty;
    internal List<ReportPrintLevel> AllReportLevel { get; } = Enum.GetValues<ReportPrintLevel>().Cast<ReportPrintLevel>().ToList();
    public ObservableCollection<AzureItemControlTemplate> AllGroupFilter { get; } = new ObservableCollection<AzureItemControlTemplate>()
    {
        new AzureItemControlTemplate(null, showDelete: false)
    };
    public ObservableCollection<AzureItemControlTemplate> AllActivities { get; } = new ObservableCollection<AzureItemControlTemplate>(
        DefaultValue.AzureLoginAuditActivities.Select((singleString, index) =>
            new AzureItemControlTemplate(singleString, showDelete: index != 0))
    );
    public ObservableCollection<AuditLogRecord> AllAuditData { get; } = new ObservableCollection<AuditLogRecord>();
    public ObservableCollection<AzureItemControlTemplate> AllScopes { get; } = new ObservableCollection<AzureItemControlTemplate>(
        DefaultValue.AzureLoginAuditPermissions.Select((singleString, index) =>
            new AzureItemControlTemplate(singleString, showDelete: index != 0))
    );
    [RelayCommand]
    private async Task SetUserCodeToClipboard(CancellationToken token)
    {
        await _uiHelper.SetTextToClipboard(UserCode);
    }
    [RelayCommand]
    private async Task OpenBrowserAsync(CancellationToken token)
    {
        _uiHelper.OpenUrlInBrowser(DefaultValue.DeviceLoginUrl);
    }
    [RelayCommand]
    private async Task LoadDataFile(CancellationToken token)
    {
        IReadOnlyList<IStorageFile> OpenFile = await _uiHelper.GetIStorageFileListForOpenFile();

        if (OpenFile.Any())
        {
            Uri SinglePath = OpenFile[0].Path;
            using (FileStream Stream = new FileStream(SinglePath.AbsolutePath, FileMode.Open, FileAccess.Read))
            {
                List<AuditLogRecord> Result = await JsonSerializer.DeserializeAsync<List<AuditLogRecord>>(Stream, cancellationToken: token);
                AllAuditData.Clear();
                foreach (AuditLogRecord SingleRecord in Result)
                {
                    AllAuditData.Add(SingleRecord);
                }
            }
        }
    }
    [RelayCommand]
    private async Task SaveDataToFile(CancellationToken token)
    {
        IStorageFile SaveFile = await _uiHelper.GetIStorageFileListForCreateFile();

        if (SaveFile is not null)
        {
            Uri SinglePath = SaveFile.Path;
            using (FileStream Stream = new FileStream(SinglePath.AbsolutePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
            {
                await JsonSerializer.SerializeAsync<List<AuditLogRecord>>(Stream, AllAuditData.ToList(), cancellationToken: token);
            }
        }
    }
    [RelayCommand]
    private async Task AddNewGroupFilter()
    {
        AllGroupFilter.Add(new AzureItemControlTemplate(null));
    }
    [RelayCommand]
    private async Task DeleteGroupFilter(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllGroupFilter.Remove(Item);
    }
    [RelayCommand]
    private async Task AddNewActivity()
    {
        AllActivities.Add(new AzureItemControlTemplate(null));
    }
    [RelayCommand]
    private async Task DeleteActivity(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllActivities.Remove(Item);
    }
    [RelayCommand]
    private async Task AddNewScope()
    {
        AllScopes.Add(new AzureItemControlTemplate(null));
    }
    [RelayCommand]
    private async Task DeleteScope(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllScopes.Remove(Item);
    }
    [RelayCommand]
    private async Task StartAzureAuditingGathering(CancellationToken token)
    {
        LoadingRingEnabled = true;
        
        AuthType Flow = Preferences.Get<AuthType>(Strings.Setting_Name_AuthType, AuthType.DeviceCode);
        GraphServiceClient Client = null;
        AzureAuth AzureAuth = new AzureAuth(Log.Logger);

        switch (Flow)
        {
            case AuthType.DeviceCode:
                DeviceCodeCredentialOptions DeviceCodeCredentialOptions = AzureAuth.CreateDeviceCodeCredentialOptions(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, DefaultValue.AppId),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, DefaultValue.TenantId),
                    CreateCallBack: false);
        
                DeviceCodeCredentialOptions.DeviceCodeCallback += (DeviceCode, sender) =>
                {
                    UserCode = DeviceCode.UserCode;
                    CopyUserCodeEnabled = true;
                    OpenBrowserEnabled = true;
        
                    return Task.CompletedTask;
                };
        
                DeviceCodeCredential DeviceCodeCredential = AzureAuth.CreateDeviceCodeCredential(DeviceCodeCredentialOptions);
        
                Client = AzureAuth.GetClientBeta(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, DefaultValue.AppId),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, DefaultValue.TenantId),
                    _uiHelper.GetContentFromObservableCollection(AllScopes),
                    Flow,
                    CodeCredential: DeviceCodeCredential);
                break;
            case AuthType.Interactive:
                Client = Client = AzureAuth.GetClientBeta(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, DefaultValue.AppId),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, DefaultValue.TenantId),
                    _uiHelper.GetContentFromObservableCollection(AllScopes),
                    Flow);
                break;
        }
        
        AzureAudit AzureAudit = new AzureAudit(Log.Logger);
        
        AuditLogQuery CreatedQuery;

        if (!ExistingQueryID.Equals(string.Empty))
        {
            CreatedQuery = await AzureAudit.GetQueryFromName(Client, ExistingQueryID);
        }
        else
        {
            DateTime StartFilterTime = SelectedStartDate.Add(SelectedStartTime);
            DateTime EndFilterTime = SelectedEndDate.Add(SelectedEndTime);

            CreatedQuery = await AzureAudit.CreateQuery(
                Client,
                StartFilterTime,
                EndFilterTime,
                _uiHelper.GetContentFromObservableCollection(AllActivities)
            );
        }

        await AzureAudit.WaitOnQuery(Client, CreatedQuery, 100);

        AuditLogRecordCollectionResponse RawResult = await AzureAudit.GetResultFromQuery(Client, CreatedQuery);

        foreach (AuditLogRecord SingleResult in RawResult.Value)
        {
            AllAuditData.Add(SingleResult);
        }
        
        ExportEnabled = true;
        LoadingRingEnabled = false;
    }
}