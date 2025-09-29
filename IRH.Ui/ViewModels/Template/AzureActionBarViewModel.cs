using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Platform.Storage;
using Avalonia.SimplePreferences;
using Azure.Identity;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using IRH.Lib;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Ui.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.Models.Message.Request;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.Resources;
using Microsoft.Graph;
using Serilog;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureActionBarViewModel : ViewModelBase
{
    [ObservableProperty]
    private List<ReportPrintLevel> _allReportLevel = Enum.GetValues<ReportPrintLevel>().ToList();
    
    [ObservableProperty] 
    private ReportPrintLevel _selectedReportLevel = DefaultValue.PrintLevel;
    
    [ObservableProperty] 
    private string _userCode = string.Empty;
    
    [ObservableProperty] 
    private bool _copyUserCodeEnabled = false;
    
    [ObservableProperty] 
    private bool _openBrowserEnabled = false;
    
    [ObservableProperty] 
    private bool _loadingRingEnabled = false;
    
    [ObservableProperty] 
    private bool _exportEnabled = false;

    [ObservableProperty] 
    private bool _shouldElevateToAppAccess = false;
    
    public required Type DataType;
    public required Type ParentViewModel;
    public required Type RequestDataType;

    private const string PropertyResponseName = "Response";
    private readonly UiHelper _uiHelper = new UiHelper();
    
    [RelayCommand]
    private async Task StartAzureGathering(CancellationToken token)
    {
        LoadingRingEnabled = true;

        AuthType Flow = Preferences.Get<AuthType>(Resources.Strings.Setting_Name_AuthType, AuthType.DeviceCode);
        GraphServiceClient Client = null;
        AzureAuth AzureAuth = new AzureAuth(Log.Logger);
        
        ObservableCollection<AzureItemControlTemplate> AllScopes  = WeakReferenceMessenger.Default.Send<AzureScopeRequestMessage>().Response;
    }

    [RelayCommand]
    private async Task SetUserCodeToClipboardCommand()
    {
        throw new NotImplementedException();
    }
    
    [RelayCommand]
    private async Task OpenBrowserAsync()
    {
        throw new NotImplementedException();
    }
    
    [RelayCommand]
    private async Task SaveDataToFile(CancellationToken token)
    {
        throw new NotImplementedException();
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
                object Data = (await JsonSerializer.DeserializeAsync(Stream, DataType, cancellationToken: token))!;
                WeakReferenceMessenger.Default.Send(Data);
            }
        }
    }
}