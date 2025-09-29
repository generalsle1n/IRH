using CommunityToolkit.Mvvm.ComponentModel;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureDeleteItemViewModel : ViewModelBase
{
    [ObservableProperty] 
    private bool _itemDeleteActive = false;
}