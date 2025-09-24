using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Ui.Lib;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureActionBarViewModel : ViewModelBase
{
    //Just used for Displaying Enum
    internal List<ReportPrintLevel> AllReportLevel { get; } = Enum.GetValues<ReportPrintLevel>().ToList();
    
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
    
    private readonly UIHelper _uiHelper = new UIHelper();
    
    [RelayCommand]
    private async Task StartAzureGathering(CancellationToken token)
    {
        throw new NotImplementedException();
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
        throw new NotImplementedException();
    }
}