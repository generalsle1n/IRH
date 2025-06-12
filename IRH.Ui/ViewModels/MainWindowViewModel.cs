using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using FluentAvalonia.UI.Controls;
using IRH.Ui.Models.Generel;
// using IRH.Ui.Models.Generel;
using IRH.Ui.Views;
using Symbol = FluentIcons.Common.Symbol;

namespace IRH.Ui.ViewModels
{
    public partial class MainWindowViewModel : ViewModelBase
    {
        [ObservableProperty]
        private UserControl _currentPage = new SettingView();

        [ObservableProperty]
        private NavigationViewItem _selectedItem;

        partial void OnSelectedItemChanged(NavigationViewItem value)
        {
            
            string TypeName = value.Tag as string;
            Type SingleType = Type.GetType(TypeName);

            if (SingleType is null)
            {
                SingleType = typeof(SettingView);
            }
            
            UserControl SingleView = (UserControl)Activator.CreateInstance(SingleType);

            CurrentPage = SingleView;
            SelectedItem = value;
        }
    }
}
