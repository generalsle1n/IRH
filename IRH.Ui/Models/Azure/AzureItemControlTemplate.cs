namespace IRH.Ui.Models.Azure;

public class AzureItemControlTemplate
{
    public AzureItemControlTemplate(string label, bool showDelete=true)
    {
        Label = label;
        ShowDelete = showDelete;
    }
    public string Label { get; }
    public bool ShowDelete { get; }
}