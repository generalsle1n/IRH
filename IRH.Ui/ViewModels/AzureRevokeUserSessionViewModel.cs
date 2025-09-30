using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using IRH.Lib;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.Session;
using IRH.Lib.Model.Azure.Session;
using IRH.Ui.Lib;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels.Template;
using Microsoft.Graph.Models;
using Serilog;

namespace IRH.Ui.ViewModels;

public partial class AzureRevokeUserSessionViewModel : AzureViewModelBase<UserSession, AzureRevokeUserSessionViewModel>
{
    [ObservableProperty]
    private AzureGroupViewModel _azureGroupViewModel = new AzureGroupViewModel();
    
    [ObservableProperty]
    private AzureScopeViewModel _azureScopeViewModel = new AzureScopeViewModel()
    {
        AllScopes = UiHelper.CreateObservableItemControlTemplateFromList(DefaultValue.AzureSessionRevokePermissions)
    };

    protected override async Task StartAzureProcessAsync(AzureGraphViewModelMessageGeneric<AzureRevokeUserSessionViewModel> message)
    {
        string[] AllGroups = UiHelper.GetContentFromObservableCollection(AzureGroupViewModel.AllGroupFilter, removeEmpty: true);

        AzureUser AzureUser = new AzureUser(Log.Logger);
        UserCollectionResponse Users = await AzureUser.GetUsersAsync(message.Client, AllGroups);
        
        AllItems.Clear();
        foreach (User SingleUser in Users.Value)
        {
            AllItems.Add(new UserSession()
            {
                User = SingleUser,
                ResetToken = false
            });
        }

        AzureSession AzureSession = new AzureSession(Log.Logger);

        foreach (UserSession SingleUserSession in AllItems)
        {
            UserSession Result = await AzureSession.ResetSingleUserSessionAsync(message.Client, SingleUserSession);
            SingleUserSession.ResetToken = Result.ResetToken;
            SingleUserSession.Response = Result.Response;
        }
        
        AzureActionBarViewModel.SetUiToProcessFinishMode();
    }
}