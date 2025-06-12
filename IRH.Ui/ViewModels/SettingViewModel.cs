using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using IRH.Lib.Model.Azure.Auth;
using IRH.Ui.Models.UI;

namespace IRH.Ui.ViewModels;

internal partial class SettingViewModel : ViewModelBase
{
    [ObservableProperty]
    private AppTheme _selectedAppTheme;
    [ObservableProperty]
    private AuthType _selectedAuthType;
    [ObservableProperty]
    private string _currentTenantID;
    [ObservableProperty]
    private string _currentAppID;
    [ObservableProperty]
    private bool _tenantIDEditEnabled = false;
    [ObservableProperty]
    private bool _appIDEditEnabled = false;
    
    internal List<AppTheme> AllAppThemes { get; } = Enum.GetValues<AppTheme>().Cast<AppTheme>().ToList();
    public List<AuthType> AllAuthTypes { get; } = Enum.GetValues<AuthType>().Cast<AuthType>().ToList();
}