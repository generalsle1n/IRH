using System.Collections.ObjectModel;
using System.Reflection;
using System.Threading.Tasks;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Ui.Models.Azure;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureSubjectViewModel : ViewModelBase
{
    [ObservableProperty]
    private ObservableCollection<AzureItemControlTemplate> _allSubjectFilter = new ObservableCollection<AzureItemControlTemplate>()
    {
        new AzureItemControlTemplate(string.Empty, false)
    };
    
    [RelayCommand]
    private async Task AddNewSubjectFilter()
    {
        AllSubjectFilter.Add(new AzureItemControlTemplate(string.Empty));
    }

    [RelayCommand]
    private async Task DeleteSubjectFilter(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllSubjectFilter.Remove(Item);
    }
}