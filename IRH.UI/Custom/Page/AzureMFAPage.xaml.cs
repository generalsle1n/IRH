using Azure.Core;
using Azure.Identity;
using IRH.Lib;
using IRH.Lib.Class.Azure.Auth;
using IRH.Lib.Class.Azure.Generel;
using IRH.Lib.Class.Azure.MFA;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.Azure.Result;
using IRH.Lib.Model.General;
using IRH.UI.Resources.Language;
using Microsoft.Graph;
using Microsoft.Graph.Beta.Models.ManagedTenants;
using Microsoft.Graph.Models;
using Serilog;
using System.Reflection;

namespace IRH.UI.Custom.Page;

public partial class AzureMFAPage : ContentPage
{
    public AzureMFAPage(ILogger logger)
	{
        _logger = logger;

		InitializeComponent();
        LoadPermissions();
        LoadOutputType();
        LoadPrintlevel();

        //PopulateUserMFASchemaToCollectionTemplate(typeof(UserMFA)).Wait();
	}

    private List<UserMFA> AllMFAUser;

    private readonly ILogger _logger;

    private void LoadPermissions()
    {
        bool IsFirst = true;
        foreach (string SinglePermission in DefaultValue.AzureMfaPermissions)
        {
            HorizontalStackLayout StackLayout = new HorizontalStackLayout()
            {
                Spacing = 5
            };

            Entry Permission = new Entry()
            {
                Placeholder = Strings.AzureMFA_Permission_PlaceHolder,
                WidthRequest = 300,
                Text = SinglePermission
            };

            Button NewEntry = new Button()
            {
                Text = Strings.Common_Add
            };
            NewEntry.Clicked += AddNewPermissionEntry;

            StackLayout.Add(Permission);
            StackLayout.Add(NewEntry);

            if (!IsFirst)
            {
                Button RemoveEntry = new Button()
                {
                    Text = Strings.Common_Delete
                };
                RemoveEntry.Clicked += RemoveCurrentEntry;

                StackLayout.Add(RemoveEntry);
            }


            MainPermissionStack.Add(StackLayout);

            IsFirst = false;
        }
    }

    private void LoadOutputType()
    {
        OutputPicker.ItemsSource = Enum.GetValues<ReportType>();
        OutputPicker.SelectedIndex = PreferenceHelper.GetIndexFromEnum<ReportType>(DefaultValue.ReportType);
    }
    
    private void LoadPrintlevel()
    {
        PrintlevelPicker.ItemsSource = Enum.GetValues<ReportPrintLevel>();
        PrintlevelPicker.SelectedIndex = PreferenceHelper.GetIndexFromEnum<ReportPrintLevel>(DefaultValue.PrintLevel);
    }

    private void AddNewGroupEntry(object sender, EventArgs e)
    {
        HorizontalStackLayout StackLayout = new HorizontalStackLayout()
        {
            Spacing = 5
        };

        Entry GroupFilter = new Entry()
        {
            Placeholder = Strings.AzureMFA_GroupFilter_Placeholder,
            WidthRequest = 300
        };

        Button NewEntry = new Button()
        {
            Text = Strings.Common_Add
        };
        NewEntry.Clicked += AddNewGroupEntry;

        
        Button RemoveEntry = new Button()
        {
            Text = Strings.Common_Delete
        };
        
        RemoveEntry.Clicked += RemoveCurrentEntry;
        
        StackLayout.Add(GroupFilter);
        StackLayout.Add(NewEntry);
        StackLayout.Add(RemoveEntry);

        MainGroupStack.Add(StackLayout);
    }

    private void AddNewPermissionEntry(object sender, EventArgs e)
    {
        HorizontalStackLayout StackLayout = new HorizontalStackLayout()
        {
            Spacing = 5
        };

        Entry GroupFilter = new Entry()
        {
            Placeholder = Strings.AzureMFA_GroupFilter_Placeholder,
            WidthRequest = 300
        };

        Button NewEntry = new Button()
        {
            Text = Strings.Common_Add
        };
        NewEntry.Clicked += AddNewPermissionEntry;

        Button RemoveEntry = new Button()
        {
            Text = Strings.Common_Delete
        };
        RemoveEntry.Clicked += RemoveCurrentEntry;

        StackLayout.Add(GroupFilter);
        StackLayout.Add(NewEntry);
        StackLayout.Add(RemoveEntry);

        MainPermissionStack.Add(StackLayout);
    }

    private void RemoveCurrentEntry(object sender, EventArgs e)
    {
        HorizontalStackLayout ParentStack = (HorizontalStackLayout)((Button)sender).Parent;
        StackLayout MainStack = (StackLayout)ParentStack.Parent;

        MainStack.Remove(ParentStack);
    }

    private void ResetLocalSettings(object sender, EventArgs e)
    {
        DeleteChildsWithSkip(MainGroupStack, 2);
        DeleteChildsWithSkip(MainPermissionStack, 1);

        LoadPermissions();
        LoadOutputType();
        LoadPrintlevel();
    }

    private void DeleteChildsWithSkip(StackLayout Layout, int Skip)
    {
        IView[] ChildsToDelete = Layout.Children.Skip(Skip).ToArray();

        foreach (IView SingleChildToDelete in ChildsToDelete)
        {
            Layout.Children.Remove(SingleChildToDelete);
        }
    }

    private string[] GetGroupIDs()
    {
        List<string> GroupIDs = new List<string>();
        List<IView> AllChildren = MainGroupStack.Children.ToList();

        foreach(IView Single in AllChildren)
        {
            if(Single is HorizontalStackLayout)
            {
                Entry SingleEntry = GetEntryFromParentGroupLayout((HorizontalStackLayout)Single);
                GroupIDs.Add(SingleEntry.Text);
            }
        }

        
        GroupIDs = GroupIDs.Where(item => item is not null).ToList();
        
        _logger.Information($"{GroupIDs.Count} groups evaluated in AzureMFA");

        return GroupIDs.ToArray();
    }

    private string[] GetPermissions()
    {
        List<string> Permissions = new List<string>();
        List<IView> AllChildren = MainPermissionStack.Children.ToList();

        foreach (IView Single in AllChildren)
        {
            if (Single is HorizontalStackLayout)
            {
                Entry SingleEntry = GetEntryFromParentGroupLayout((HorizontalStackLayout)Single);
                Permissions.Add(SingleEntry.Text);
            }
        }


        Permissions = Permissions.Where(item => item is not null).ToList();

        _logger.Information($"{Permissions.Count} permissions evaluated in AzureMFA");

        return Permissions.ToArray();
    }

    private Entry GetEntryFromParentGroupLayout(HorizontalStackLayout Parent)
    {
        return (Entry)Parent.Children[0];
    }

    private async void StartGathering(object sender, EventArgs e)
    {
        StartProcessToGather.IsEnabled = false;
        AuthType Flow = PreferenceHelper.GetEnumFromIndex<AuthType>(Preferences.Get(PreferenceHelper.DefaultAuthTypeName, 0));
        GraphServiceClient Client = null;
        
        switch (Flow)
        {
            case AuthType.DeviceCode:
                AzureAuth AzureAuth = new AzureAuth(_logger);

                DeviceCodeCredentialOptions DeviceCodeCredentialOptions = AzureAuth.CreateDeviceCodeCredentialOptions(
                    Preferences.Get(PreferenceHelper.DefaultAppIDName, ""),
                    Preferences.Get(PreferenceHelper.DefaultTenantIDName, ""),
                    CreateCallBack: false);

                DeviceCodeCredentialOptions.DeviceCodeCallback += (DeviceCode, sender) =>
                {
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        DeviceCodeOutput.Text = DeviceCode.UserCode;
                        DeviceCodeOutput.IsVisible = true;

                        LoadingIndicator.IsVisible = true;
                        LoadingIndicator.IsRunning = true;

                        OpenBrowser.IsVisible = true;
                    });
                    return Task.CompletedTask;
                };

                DeviceCodeCredential DeviceCodeCredential = AzureAuth.CreateDeviceCodeCredential(DeviceCodeCredentialOptions);

                await DeviceCodeCredential.GetTokenAsync(new TokenRequestContext(GetPermissions()));

                OpenBrowser.IsVisible = false;

                Client = AzureAuth.GetClient(
                    Preferences.Get(PreferenceHelper.DefaultAppIDName, ""),
                    Preferences.Get(PreferenceHelper.DefaultTenantIDName, ""),
                    GetPermissions(),
                    Flow,
                    CodeCredential: DeviceCodeCredential);

                break;
            case AuthType.Interactive:
                break;
        }
        AzureUser AzureUser = new AzureUser(_logger);
        var AllUser = await AzureUser.GetUsersAsync(Client, GetGroupIDs());

        AzureMFA AzureMFA = new AzureMFA(_logger);
        AllMFAUser = (await AzureMFA.GetAllUsersMFA(Client, AllUser)).OrderByDescending(user => user.AllMFACount).ToList();

        await PopulateUserMFASchemaToCollectionTemplate(typeof(UserMFA));
        MainUserMFACollection.
        MainUserMFACollection.ItemsSource = AllMFAUser;

        LoadingIndicator.IsRunning = false;
        LoadingIndicator.IsVisible = false;

        StartProcessToGather.IsEnabled = true;
    }

    private async void OpenBrowserDeviceLogin(object sender, EventArgs e)
    {
        await Browser.OpenAsync("https://microsoft.com/devicelogin");
    }

    private async Task PopulateUserMFASchemaToCollectionTemplate(Type SingleObject)
    {
        ReportPrintLevel Current = PreferenceHelper.GetEnumFromIndex<ReportPrintLevel>(PrintlevelPicker.SelectedIndex);
        PropertyInfo[] AllProperties = SingleObject.GetProperties();
        Console.WriteLine();

        if(Current == ReportPrintLevel.Brief || Current == ReportPrintLevel.Info || Current == ReportPrintLevel.Detailed || Current == ReportPrintLevel.Hacky)
        {
            MainUserMFACollection.ItemTemplate = new DataTemplate(() =>
            {
                HorizontalStackLayout Layout = new HorizontalStackLayout()
                {
                    Spacing = 5
                };

                Label NameLabel = new Label();
                NameLabel.SetBinding(Label.TextProperty, static (UserMFA user) => user.User.UserPrincipalName);
                NameLabel.FontAttributes = FontAttributes.Bold;

                Label Count = new Label();
                Count.SetBinding(Label.TextProperty, static (UserMFA user) => user.AllMFACount);
                
                Layout.Add(NameLabel);
                Layout.Add(Count);

                return Layout;
            });
        }
    }
}