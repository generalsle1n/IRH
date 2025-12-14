using System.Collections.ObjectModel;
using System.Threading.Tasks;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Ui.Models.Azure;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureGroupViewModel : ViewModelBase
{
    [ObservableProperty]
    private ObservableCollection<AzureItemControlTemplate> _allGroupFilter = new ObservableCollection<AzureItemControlTemplate>()
    {
        new AzureItemControlTemplate(string.Empty, false)
    };
    
    [RelayCommand]
    private async Task AddNewGroupFilter()
    {
        AllGroupFilter.Add(new AzureItemControlTemplate(string.Empty));
    }

    [RelayCommand]
    private async Task DeleteGroupFilter(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllGroupFilter.Remove(Item);
    }
}