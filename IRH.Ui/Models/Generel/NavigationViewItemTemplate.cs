using System;
using Avalonia.Media;
using FluentIcons.Common;

namespace IRH.Ui.Models.Generel;

public class NavigationViewItemTemplate
{
    public NavigationViewItemTemplate(Type type, Symbol symbol)
    {
        ModelType = type;
        Label = type.Name.Replace("ViewModel", "");
        Symbol = symbol;
    }
    
    public string Label { get; }
    public Type ModelType { get; }
    public Symbol Symbol { get; }
}