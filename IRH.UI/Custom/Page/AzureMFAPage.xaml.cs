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
using Microsoft.Graph.Models;
using Serilog;

namespace IRH.UI.Custom.Page;

public partial class AzureMFAPage : ContentPage
{
    public AzureMFAPage(ILogger logger)
	{
        _logger = logger;

		InitializeComponent();
        LoadPermissions();
        LoadOutputType();
	}

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
        
    }

    private async void OpenBrowserDeviceLogin(object sender, EventArgs e)
    {
        await Browser.OpenAsync("https://microsoft.com/devicelogin");
    }
}