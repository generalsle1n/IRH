using System;
using Avalonia.Controls;
using Avalonia.SimplePreferences;
using CommunityToolkit.Mvvm.ComponentModel;
using FluentAvalonia.UI.Controls;
using IRH.Ui.Resources;
using IRH.Ui.Views;

namespace IRH.Ui.ViewModels
{
    public partial class MainWindowViewModel : ViewModelBase
    {
        [ObservableProperty]
        private UserControl _currentPage = new SettingView()
        {
            DataContext = new SettingViewModel()
        };

        [ObservableProperty]
        private NavigationViewItem _selectedItem;

        [ObservableProperty]
        private bool _experimentalFeaturesEnabled = Preferences.Get<bool>(Strings.Setting_Name_ExperimentalEnabled, false);
        
        partial void OnSelectedItemChanged(NavigationViewItem value)
        {
            string ViewTypeName, ViewModelTypeName = null;
            Type ViewType, ViewModelType = null;
            
            if (!(value.Name is not null && value.Name.Equals("SettingsItem")))
            {
                string[] SplitType = (value.Tag as string).Split(";");
                ViewTypeName = SplitType[0];
                ViewModelTypeName = SplitType[1];

                ViewType = Type.GetType(ViewTypeName);
                ViewModelType = Type.GetType(ViewModelTypeName);
            }
            else
            {
                ViewType = typeof(SettingView);
                ViewModelType = typeof(SettingViewModel);
            }

            UserControl SingleView = (UserControl)Activator.CreateInstance(ViewType);
            ViewModelBase SingleViewModel = (ViewModelBase)Activator.CreateInstance(ViewModelType);
            
            SingleView.DataContext = SingleViewModel;
            
            CurrentPage = SingleView;
            SelectedItem = value;
        }
    }
}
