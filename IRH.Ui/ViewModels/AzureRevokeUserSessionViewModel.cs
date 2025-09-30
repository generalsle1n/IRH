using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.SimplePreferences;
using Azure.Identity;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.Session;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Azure.Result;
using IRH.Lib.Model.Azure.Session;
using IRH.Ui.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.Resources;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog;
using Application = Avalonia.Application;

namespace IRH.Ui.ViewModels;

public partial class AzureRevokeUserSessionViewModel : ViewModelBase
{
    
    
    private UiHelper _uiHelper = new UiHelper();
    [ObservableProperty] 
    private bool _openBrowserEnabled = false;
    [ObservableProperty] 
    private string _userCode;
    [ObservableProperty] 
    private bool _copyUserCodeEnabled = false;
    [ObservableProperty] 
    private ReportPrintLevel _selectedReportLevel = DefaultValue.PrintLevel;
    [ObservableProperty] 
    private bool _loadingRingEnabled = false;
    [ObservableProperty] 
    private bool _exportEnabled = false;
    
    public ObservableCollection<UserSession> AllUserSessionData { get; } = new ObservableCollection<UserSession>();
    public ObservableCollection<AzureItemControlTemplate> AllGroupFilter { get; } = new ObservableCollection<AzureItemControlTemplate>()
    {
        new AzureItemControlTemplate(null, showDelete: false)
    };
    public ObservableCollection<AzureItemControlTemplate> AllScopes { get; } = new ObservableCollection<AzureItemControlTemplate>(
        DefaultValue.AzureSessionPermissions.Select((singleString, index) =>
            new AzureItemControlTemplate(singleString, showDelete: index != 0))
    );
    
    internal List<ReportPrintLevel> AllReportLevel { get; } = Enum.GetValues<ReportPrintLevel>().Cast<ReportPrintLevel>().ToList();
    
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
    private async Task SetUserCodeToClipboard()
    {
        await _uiHelper.SetTextToClipboard(UserCode);
    }

    [RelayCommand]
    private async Task OpenBrowserAsync()
    {
        await _uiHelper.OpenUrlInBrowserAsync(DefaultValue.DeviceLoginUrl);
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
                List<UserSession> Result = await JsonSerializer.DeserializeAsync<List<UserSession>>(Stream, cancellationToken: token);
                AllUserSessionData.Clear();
                foreach (UserSession SingleUser in Result)
                {
                    AllUserSessionData.Add(SingleUser);
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
                await JsonSerializer.SerializeAsync<List<UserSession>>(Stream, AllUserSessionData.ToList(), cancellationToken: token);
            }
        }
    }

    [RelayCommand]
    private async Task StartAzureGathering(CancellationToken token)
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

                Client = await AzureAuth.GetClientAsync(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, DefaultValue.AppId),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, DefaultValue.TenantId),
                    _uiHelper.GetContentFromObservableCollection(AllScopes),
                    Flow,
                    CodeCredential: DeviceCodeCredential);
                break;
            case AuthType.Interactive:
                Client = Client = await AzureAuth.GetClientAsync(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, DefaultValue.AppId),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, DefaultValue.TenantId),
                    _uiHelper.GetContentFromObservableCollection(AllScopes),
                    Flow);
                break;
        }

        string[] AllGroups = _uiHelper.GetContentFromObservableCollection(AllGroupFilter, removeEmpty: true);

        AzureUser AzureUser = new AzureUser(Log.Logger);
        UserCollectionResponse AllUser = await AzureUser.GetUsersAsync(Client, AllGroups, token);
        
        foreach (User SingleUser in AllUser.Value)
        {
            AllUserSessionData.Add(new UserSession()
            {
                User = SingleUser,
                ResetToken = false
            });
        }

        AzureSession AzureSession = new AzureSession(Log.Logger);

        foreach (UserSession SingleUserSession in AllUserSessionData)
        {
            UserSession Result = await AzureSession.ResetSingleUserSessionAsync(Client, SingleUserSession);
            SingleUserSession.ResetToken = Result.ResetToken;
            SingleUserSession.Response = Result.Response;
        }
        
        AzureActionBarViewModel.SetUiToProcessFinishMode();
    }
}