using System;
using System.IO;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Media;
using FluentAvalonia.UI.Controls;
using FluentAvalonia.UI.Windowing;
using Serilog;

namespace IRH.Ui.Views
{
    public partial class MainWindow : AppWindow
    {
        private const string _logFolerName = "logs";
        private const string _logFileName = "Log.txt";
        public MainWindow()
        {
            InitializeComponent();
            SetupLogger();
        }

        private void SetupLogger()
        {
            Assembly Current = Assembly.GetExecutingAssembly();
            string CurrentLocation = Path.GetDirectoryName(Current.Location);
            string LogFolder = Path.Combine(CurrentLocation, _logFolerName);
        
            if (!Directory.Exists(LogFolder))
            {
                Directory.CreateDirectory(LogFolder);
            }
        
            string LogFilePath = Path.Combine(LogFolder, _logFileName);
        
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug() 
                .WriteTo.Console()
                .WriteTo.File(LogFilePath, rollingInterval: RollingInterval.Day)
                .CreateLogger();
            Log.Information("Application is starting...");
        }
    }
}