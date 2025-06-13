using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using Avalonia.SimplePreferences;
using Azure.Identity;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.MFA;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Azure.Result;
using IRH.Ui.Models.Azure;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog;
using Application = Avalonia.Application;
using Strings = IRH.Ui.Resources.Strings;

namespace IRH.Ui.ViewModels;
public partial class AzureMFAViewModel : ViewModelBase
{
    [ObservableProperty]
    private ReportPrintLevel _selectedReportLevel = DefaultValue.PrintLevel;
    
    [ObservableProperty]
    private bool _openBrowserEnabled = false;
    
    [ObservableProperty]
    private string _userCode;
    
    [ObservableProperty]
    private bool _copyUserCodeEnabled = false;
    [ObservableProperty]
    private bool _loadingRingEnabled = false;
    public ObservableCollection<AzureMFAItemControlTemplate> AllGroupFilter { get; }= new ObservableCollection<AzureMFAItemControlTemplate>()
    {
        new AzureMFAItemControlTemplate(null, showDelete:false)
    };

    public ObservableCollection<UserMFA> AllUserMFA { get; } = new ObservableCollection<UserMFA>();
    
    public ObservableCollection<AzureMFAItemControlTemplate> AllScopes { get; }= new ObservableCollection<AzureMFAItemControlTemplate>(
        DefaultValue.AzureMfaPermissions.Select((singleString, index) => new AzureMFAItemControlTemplate(singleString,showDelete:index != 0))
    );
    
    internal List<ReportPrintLevel> AllReportLevel { get; } = Enum.GetValues<ReportPrintLevel>().Cast<ReportPrintLevel>().ToList();

    [RelayCommand]
    private async Task AddNewGroupFilter()
    {
        AllGroupFilter.Add(new AzureMFAItemControlTemplate(null));
    }
    
    [RelayCommand]
    private async Task DeleteGroupFilter(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureMFAItemControlTemplate Item = SingleButton.DataContext as AzureMFAItemControlTemplate;
        AllGroupFilter.Remove(Item);
    }
    
    [RelayCommand]
    private async Task AddNewScope()
    {
        AllScopes.Add(new AzureMFAItemControlTemplate(null));
    }
    
    [RelayCommand]
    private async Task DeleteScope(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureMFAItemControlTemplate Item = SingleButton.DataContext as AzureMFAItemControlTemplate;
        AllScopes.Remove(Item);
    }

    private string[] GetGroups()
    {
        List<string> Groups = new List<string>();

        foreach (AzureMFAItemControlTemplate SingleEntry in AllGroupFilter)
        {
            if (SingleEntry.Label is not null)
            {
                Groups.Add(SingleEntry.Label);
            }
        }
        
        return Groups.ToArray();
    }
    
    private string[] GetPermission()
    {
        List<string> Permissions = new List<string>();

        foreach (AzureMFAItemControlTemplate SingleEntry in AllScopes)
        {
            if (SingleEntry.Label is not null)
            {
                Permissions.Add(SingleEntry.Label);
            }
        }
        
        return Permissions.ToArray();
    }

    [RelayCommand]
    private async Task OpenBrowserAsync()
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;
        ILauncher Launcher = TopLevel.GetTopLevel(MainWindow).Launcher;
        await Launcher.LaunchUriAsync(DefaultValue.DeviceLoginUrl);
    }
    
    [RelayCommand]
    private async Task SetUserCodeToClipboard()
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;
        IClipboard Clipboard = MainWindow.Clipboard;
        
        await Clipboard.SetTextAsync(UserCode);
    }

    [RelayCommand]
    private async Task StartAzureGathering()
    {
        LoadingRingEnabled = true;
        
        AuthType Flow = Preferences.Get<AuthType>(Strings.Setting_Name_AuthType, AuthType.DeviceCode);
        GraphServiceClient Client = null;

        switch (Flow)
        {
            case AuthType.DeviceCode:
                AzureAuth AzureAuth = new AzureAuth(Log.Logger);
                
                DeviceCodeCredentialOptions DeviceCodeCredentialOptions = AzureAuth.CreateDeviceCodeCredentialOptions(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, null),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, null),
                    CreateCallBack: false);
                
                DeviceCodeCredentialOptions.DeviceCodeCallback += (DeviceCode, sender) =>
                {
                    UserCode = DeviceCode.UserCode;
                    CopyUserCodeEnabled = true;
                    OpenBrowserEnabled = true;

                    return Task.CompletedTask;
                };
                
                DeviceCodeCredential DeviceCodeCredential = AzureAuth.CreateDeviceCodeCredential(DeviceCodeCredentialOptions);
  
                Client = AzureAuth.GetClient(
                    Preferences.Get<String>(Strings.Setting_Name_AppID, null),
                    Preferences.Get<String>(Strings.Setting_Name_TenantID, null),
                    GetPermission(),
                    Flow,
                    CodeCredential: DeviceCodeCredential);
                break;
        }
        
        string[] AllGroups = GetGroups();
        
        AzureUser AzureUser = new AzureUser(Log.Logger);
        UserCollectionResponse AllUser = await AzureUser.GetUsersAsync(Client, AllGroups);

        AzureMFA AzureMFA = new AzureMFA(Log.Logger);
        List<UserMFA> AllMFAUserResult = (await AzureMFA.GetAllUsersMFA(Client, AllUser));

        foreach (UserMFA SingleUser in AllMFAUserResult)
        {
            AllUserMFA.Add(SingleUser);
        }
        
        LoadingRingEnabled = false;
    }
}