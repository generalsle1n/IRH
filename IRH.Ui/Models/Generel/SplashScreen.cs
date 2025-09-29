using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Svg.Skia;
using FluentAvalonia.UI.Windowing;

namespace IRH.Ui.Models.Generel;

public class SplashScreen : IApplicationSplashScreen
{
    public Task RunTasks(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public string AppName { get; } = "IRH.Ui";
    public IImage AppIcon { get; } = new SvgImage()
    {
        Source = SvgSource.LoadFromStream(AssetLoader.Open(new Uri("avares://IRH.Ui/Assets/IRH-logo.svg")))
    };
    public object SplashScreenContent { get; }
    public int MinimumShowTime { get; } = 2000;
}