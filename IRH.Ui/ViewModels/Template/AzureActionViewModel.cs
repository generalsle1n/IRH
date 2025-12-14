using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using IRH.Ui.Models.Azure;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureActionViewModel : ViewModelBase
{
    [ObservableProperty] 
    private string _selectedAction;
    internal ObservableCollection<string> AllActions { get; set; }
}