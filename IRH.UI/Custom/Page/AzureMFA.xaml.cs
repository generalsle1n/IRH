using IRH.Lib;
using IRH.Lib.Model.Azure.Reporting;
using IRH.Lib.Model.General;
using IRH.UI.Resources.Language;

namespace IRH.UI.Custom.Page;

public partial class AzureMFA : ContentPage
{
	public AzureMFA()
	{
		InitializeComponent();
        LoadPermissions();
        LoadOutputType();
	}

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
}