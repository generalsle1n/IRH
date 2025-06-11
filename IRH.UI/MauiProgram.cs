using CommunityToolkit.Maui;
using IRH.UI.Custom;
using Microsoft.Extensions.Logging;
using Serilog;
using System.Reflection;
using ILogger = Serilog.ILogger;

namespace IRH.UI
{
    public static class MauiProgram
    {
        private const string _logFolderName = "Logs";
        private const string _logFileName = "log.txt";
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .UseMauiCommunityToolkit()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                    fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
                });
#if DEBUG
            builder.Logging.AddDebug();
#endif
            
            Assembly Current = Assembly.GetExecutingAssembly();

            string Location = Path.GetDirectoryName(Current.Location);
            string AbsoluteFolderPath = Path.Combine(Location, _logFolderName);

            if (!Path.Exists(AbsoluteFolderPath))
            {
                Directory.CreateDirectory(AbsoluteFolderPath);
            }

            string AbsoluteLogPath = Path.Combine(AbsoluteFolderPath, _logFileName);

            ILogger logger = new LoggerConfiguration()
                    .WriteTo.File(AbsoluteLogPath)
                    .MinimumLevel.Verbose()
                    .CreateLogger();

            builder.Services.AddSingleton<ILogger>(logger);

            PreferenceHelper.LoadInitData();

            return builder.Build();
        }
    }
}
