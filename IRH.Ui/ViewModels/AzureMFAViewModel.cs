using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using Avalonia.SimplePreferences;
using Azure.Identity;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IRH.Lib;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.MFA;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Azure.Result;
using IRH.Ui.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.Models.Message.Send;
using IRH.Ui.ViewModels.Base;
using IRH.Ui.ViewModels.Template;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Serilog;
using Application = Avalonia.Application;
using Strings = IRH.Ui.Resources.Strings;

namespace IRH.Ui.ViewModels;
public partial class AzureMFAViewModel : AzureViewModelBase<UserMFA, AzureMFAViewModel>
{
    [ObservableProperty]
    private AzureGroupViewModel _azureGroupViewModel = new AzureGroupViewModel();

    [ObservableProperty]
    private AzureScopeViewModel _azureScopeViewModel = new AzureScopeViewModel()
    {
        AllScopes = UiHelper.CreateObservableItemControlTemplateFromList(DefaultValue.AzureMfaPermissions)
    };

    protected override async Task StartAzureProcessAsync(AzureGraphViewModelMessageGeneric<AzureMFAViewModel> message)
    {
        string[] AllGroups = UiHelper.GetContentFromObservableCollection(AzureGroupViewModel.AllGroupFilter, removeEmpty: true);

        AzureUser AzureUser = new AzureUser(Log.Logger);
        UserCollectionResponse Users = await AzureUser.GetUsersAsync(message.Client, AllGroups);

        AzureMFA AzureMFA = new AzureMFA(Log.Logger);

        List<UserMFA> AllMFAUserResult = await AzureMFA.GetAllUsersMFA(message.Client, Users);

        AllItems.Clear();
        foreach (UserMFA SingleUser in AllMFAUserResult)
        {
            AllItems.Add(SingleUser);
        }

        AzureActionBarViewModel.SetUiToProcessFinishMode();
    }
}