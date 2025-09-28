using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Ui.Models.Azure;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureScopeViewModel : ViewModelBase
{
    internal ObservableCollection<AzureItemControlTemplate> AllScopes { get; set; }
    public required ObservableCollection<AzureItemControlTemplate> AllScopes { get; set; }

    [RelayCommand]
    private async Task AddNewScope()
    {
        AllScopes.Add(new AzureItemControlTemplate(null));
    }

    [RelayCommand]
    private async Task DeleteScope(object Sender)
    {
        Button SingleButton = Sender as Button;
        AzureItemControlTemplate Item = SingleButton.DataContext as AzureItemControlTemplate;
        AllScopes.Remove(Item);
    }
}