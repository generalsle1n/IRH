using CommunityToolkit.Mvvm.ComponentModel;
using IRH.Lib;
using IRH.Ui.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.ViewModels.Template;

namespace IRH.Ui.ViewModels;

public partial class AzureMailViewModel : ViewModelBase
{
    [ObservableProperty]
    private AzureActionBarViewModel _azureActionBarViewModel = new AzureActionBarViewModel();
    
    [ObservableProperty]
    private AzureScopeViewModel _azureScopeViewModel = new AzureScopeViewModel()
    {
        AllScopes = UIHelper.CreateObservableItemControlTemplateFromList(DefaultValue.AzureMailCleanupPermissions)
    };
    
    [ObservableProperty]
    private AzureGroupViewModel _azureGroupViewModel = new AzureGroupViewModel();
    [ObservableProperty]
    private AzureDateViewModel _azureDateViewModel = new AzureDateViewModel();
}