using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.General;
using IRH.UI.Resources.Language;
using System.Globalization;

namespace IRH.UI.Custom.Page;

public partial class Settings : ContentPage
{
	public Settings()
	{
        InitializeComponent();
        LoadData();
    }

    private void OnSaveClick(object sender, EventArgs e)
    {
        Preferences.Set(PreferenceHelper.DefaultTenantIDName, TenantID.Text);
        Preferences.Set(PreferenceHelper.DefaultAppIDName, AppID.Text);
        Preferences.Set(PreferenceHelper.DefaultAuthTypeName, AuthTypes.SelectedIndex);
        Preferences.Set(PreferenceHelper.DefaultLanguageName, Language.SelectedIndex);

        DisplayAlert(Strings.Settings_SaveAlert_Title, Strings.Settings_SaveAlert_Text, Strings.Common_Ok);
    }

    private void OnResetClick(object sender, EventArgs e)
    {
        PreferenceHelper.LoadInitData(Reset: true);
        LoadData();
        DisplayAlert(Strings.Settings_ResetAlert_Title, Strings.Settings_ResetAlert_Text, Strings.Common_Ok);
    }

    private void LoadData()
    {
        TenantID.Text = Preferences.Get(PreferenceHelper.DefaultTenantIDName, string.Empty);
        AppID.Text = Preferences.Get(PreferenceHelper.DefaultAppIDName, string.Empty);
        
        AuthTypes.ItemsSource = Enum.GetValues<AuthType>();
        AuthTypes.SelectedIndex = Preferences.Get(PreferenceHelper.DefaultAuthTypeName, 0);

        Language.ItemsSource = Enum.GetValues<Language>();
        Language.SelectedIndex = Preferences.Get(PreferenceHelper.DefaultLanguageName, 0);
    }
}