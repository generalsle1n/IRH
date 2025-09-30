using Avalonia.Controls;
using Avalonia.Interactivity;
using CommunityToolkit.Mvvm.Messaging;

namespace IRH.Ui.Views.Template;

public partial class AzureScopeView : UserControl
{
    public AzureScopeView()
    {
        InitializeComponent();
    }
 
    protected override void OnUnloaded(RoutedEventArgs e)
    {
        WeakReferenceMessenger.Default.UnregisterAll(DataContext);
        base.OnUnloaded(e);
    }
}