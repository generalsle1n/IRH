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
}