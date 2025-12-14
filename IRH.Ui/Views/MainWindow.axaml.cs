using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Media;
using FluentAvalonia.UI.Controls;
using FluentAvalonia.UI.Windowing;
using IRH.Ui.Lib;
using IRH.Ui.Models.Generel;
using Serilog;

namespace IRH.Ui.Views
{
    public partial class MainWindow : AppWindow
    {
        private const string _logFolerName = "logs";
        private const string _logFileName = "Log.txt";
        
        private DataMessageRouter _dataMessageRouter = new DataMessageRouter();
        
        public MainWindow()
        {
            InitializeComponent();
            SetupLogger();
            SplashScreen = new SplashScreen();
        }

        private void SetupLogger()
        {
            Process Current = Process.GetCurrentProcess();
            
            string CurrentLocation = Path.GetDirectoryName(Current.MainModule.FileName);
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