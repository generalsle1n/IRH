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
    private const string _filePickerDisplayName = "Json";
    private const string _fileNamePrefix = "Result-";
    private const string _fileNameSuffix = ".json";
    private const string _filePickerFilter = $"*{_fileNameSuffix}";
    private const string _dateFormat = "dd_MM_yyyy-HH_mm_ss";
    private const string _fileAppleIdentifier = "public.json";
    private const string _fileMimeType = "application/json";
    
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
    [ObservableProperty]
    private bool _exportEnabled = false;
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
    private async Task SaveDataToFile(CancellationToken token)
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;
        
        IStorageFile SaveFile = await MainWindow.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions()
        {
            Title = Strings.AzureMFA_SaveFile_Title,
            FileTypeChoices = new List<FilePickerFileType>()
            {
                new FilePickerFileType(_filePickerDisplayName)
                {
                    Patterns = new List<string>()
                    {
                        _filePickerFilter
                    },
                    AppleUniformTypeIdentifiers = new List<string>()
                    {
                        _fileAppleIdentifier
                    },
                    MimeTypes = new List<string>()
                    {
                        _fileMimeType
                    }
                }
            },
            ShowOverwritePrompt = true,
            SuggestedFileName = $"{_fileNamePrefix}{DateTimeOffset.Now.ToString(_dateFormat)}{_fileNameSuffix}",
        });

        if (SaveFile is not null)
        {
            Uri SinglePath = SaveFile.Path;
            using (FileStream Stream = new FileStream(SinglePath.AbsolutePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
            {
                await JsonSerializer.SerializeAsync<List<UserMFA>>(Stream, AllUserMFA.ToList(), cancellationToken: token);
            }
        }
    }

    [RelayCommand]
    private async Task LoadDataFile(CancellationToken token)
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;
        
        IReadOnlyList<IStorageFile> OpenFile = await MainWindow.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions()
        {
            Title = Strings.AzureMFA_SaveFile_Title,
            AllowMultiple = false,
            FileTypeFilter = new List<FilePickerFileType>()
            {
                new FilePickerFileType(_filePickerDisplayName)
                {
                    Patterns = new List<string>()
                    {
                        _filePickerFilter
                    },
                    AppleUniformTypeIdentifiers = new List<string>()
                    {
                        _fileAppleIdentifier
                    },
                    MimeTypes = new List<string>()
                    {
                        _fileMimeType
                    }
                }
            }
        });

        if (OpenFile.Any())
        {
            Uri SinglePath = OpenFile[0].Path;
            using (FileStream Stream = new FileStream(SinglePath.AbsolutePath, FileMode.Open, FileAccess.Read))
            {
                List<UserMFA> Result = await JsonSerializer.DeserializeAsync<List<UserMFA>>(Stream, cancellationToken: token);
                AllUserMFA.Clear();
                foreach (UserMFA SingleUser in Result)
                {
                    AllUserMFA.Add(SingleUser);
                }
            }
        }
    }
    
    [RelayCommand]
    private async Task StartAzureGathering(CancellationToken token)
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