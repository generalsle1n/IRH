using System;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using FluentAvalonia.UI.Controls;
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

        partial void OnSelectedItemChanged(NavigationViewItem value)
        {
            string[] SplitType = (value.Tag as string).Split(";");
            
            string ViewTypeName = SplitType[0];
            string ViewModelTypeName = SplitType[1];
            
            Type ViewType = Type.GetType(ViewTypeName) ?? typeof(SettingView);
            Type ViewModelType = Type.GetType(ViewTypeName) ?? typeof(SettingViewModel);
            
            UserControl SingleView = (UserControl)Activator.CreateInstance(ViewType);
            ViewModelBase SingleViewModel = (ViewModelBase)Activator.CreateInstance(ViewModelType);
            
            SingleView.DataContext = SingleViewModel;
            
            CurrentPage = SingleView;
            SelectedItem = value;
        }
    }
}
