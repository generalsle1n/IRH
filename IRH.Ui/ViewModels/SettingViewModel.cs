using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.SimplePreferences;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Model.Azure.Auth;
using IRH.Ui.Models.UI;
using Strings = IRH.Ui.Resources.Strings;

namespace IRH.Ui.ViewModels;

internal partial class SettingViewModel : ViewModelBase
{
    public SettingViewModel()
    {
        SetAppTheme();
    }
    
    [ObservableProperty]
    private AppTheme _selectedAppTheme = Preferences.Get<AppTheme>(Strings.Setting_Name_AppTheme, AppTheme.System);
    [ObservableProperty]
    private AuthType _selectedAuthType = Preferences.Get<AuthType>(Strings.Setting_Name_AuthType, DefaultValue.AuthType);
    [ObservableProperty]
    private string _currentTenantID = Preferences.Get<string>(Strings.Setting_Name_TenantID, DefaultValue.TenantID);
    [ObservableProperty]
    private string _currentAppID = Preferences.Get<string>(Strings.Setting_Name_AppID, DefaultValue.AppID);
    [ObservableProperty]
    private bool _tenantIDEditEnabled = Preferences.Get<bool>(Strings.Setting_Name_TenantIDEditEnabled, false);
    [ObservableProperty]
    private bool _appIDEditEnabled = Preferences.Get<bool>(Strings.Setting_Name_AppIDEditEnabled, false);
    internal List<AppTheme> AllAppThemes { get; } = Enum.GetValues<AppTheme>().Cast<AppTheme>().ToList();
    public List<AuthType> AllAuthTypes { get; } = Enum.GetValues<AuthType>().Cast<AuthType>().ToList();

    [RelayCommand]
    private async Task ResetTenantID()
    {
        await Preferences.SetAsync<string>(Strings.Setting_Name_TenantID, DefaultValue.TenantID);
        CurrentTenantID = DefaultValue.TenantID;
    }
    [RelayCommand]
    private async Task ResetAppID()
    {
        await Preferences.SetAsync<string>(Strings.Setting_Name_AppID, DefaultValue.AppID);
        CurrentAppID = DefaultValue.AppID;
    }
    
    [RelayCommand]
    private async Task ResetAllSettings(CancellationToken token)
    {
        await Preferences.ClearAsync(cancellationToken: token);
    }

    partial void OnSelectedAuthTypeChanged(AuthType value)
    {
        Preferences.Set<AuthType>(Strings.Setting_Name_AuthType, value);
        SelectedAuthType = value;
    }

    partial void OnCurrentTenantIDChanged(string value)
    {
        Preferences.Set<string>(Strings.Setting_Name_TenantID, value);
        CurrentTenantID = value;
    }
    partial void OnCurrentAppIDChanged(string value)
    {
        Preferences.Set<string>(Strings.Setting_Name_AppID, value);
        CurrentAppID = value;
    }

    partial void OnTenantIDEditEnabledChanged(bool value)
    {
        Preferences.Set<bool>(Strings.Setting_Name_TenantIDEditEnabled, value);
        TenantIDEditEnabled = value;
    }

    partial void OnAppIDEditEnabledChanged(bool value)
    {
        Preferences.Set<bool>(Strings.Setting_Name_AppIDEditEnabled, value);
        AppIDEditEnabled = value;
    }

    private void SetAppTheme()
    {
        switch (SelectedAppTheme)
        {
            case AppTheme.Light:
                Application.Current!.RequestedThemeVariant = ThemeVariant.Light;
                break;
            case AppTheme.Dark:
                Application.Current!.RequestedThemeVariant = ThemeVariant.Dark;
                break;
            case AppTheme.System:
                Application.Current!.RequestedThemeVariant = ThemeVariant.Default;
                break;
        }
    }
    
    partial void OnSelectedAppThemeChanged(AppTheme value)
    {
        Preferences.Set<AppTheme>(Strings.Setting_Name_AppTheme, value);
        SelectedAppTheme = value;
        
        SetAppTheme();
    }
}