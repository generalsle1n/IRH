using System.Collections.ObjectModel;
using System.Threading.Tasks;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.Input;
using IRH.Ui.Models.Azure;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureGroupViewModel : ViewModelBase
{
    internal ObservableCollection<AzureItemControlTemplate> AllGroupFilter { get; set; } = new ObservableCollection<AzureItemControlTemplate>()
    {
        new AzureItemControlTemplate(null, false)
    };
    
    [RelayCommand]
    private async Task AddNewGroupFilter()
    {
        AllGroupFilter.Add(new AzureItemControlTemplate(null));
    }

    [RelayCommand]
    private async Task DeleteGroupFilter(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllGroupFilter.Remove(Item);
    }
}