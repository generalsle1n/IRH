namespace IRH.Ui.Models.Azure;

public class AzureMFAItemControlTemplate
{
    public AzureMFAItemControlTemplate(string label, bool showDelete=true)
    {
        Label = label;
        ShowDelete = showDelete;
    }
    public string Label { get; }
    public bool ShowDelete { get; }
}