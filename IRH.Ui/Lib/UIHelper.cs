using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using IRH.Lib;
using IRH.Ui.Models.Azure;
using IRH.Ui.Resources;

namespace IRH.Ui.Lib;

public class UIHelper
{
    private const string _filePickerDisplayName = "Json";
    private const string _fileNamePrefix = "Result-";
    private const string _fileNameSuffix = ".json";
    private const string _filePickerFilter = $"*{_fileNameSuffix}";
    private const string _dateFormat = "dd_MM_yyyy-HH_mm_ss";
    private const string _fileAppleIdentifier = "public.json";
    private const string _fileMimeType = "application/json";
    internal async Task SetTextToClipboard(string text)
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;
        IClipboard Clipboard = MainWindow.Clipboard;

        await Clipboard.SetTextAsync(text);
    }

    internal static ObservableCollection<AzureItemControlTemplate> CreateObservableItemControlTemplateFromList(List<string> Items)
    {
        ObservableCollection<AzureItemControlTemplate> Result = new ObservableCollection<AzureItemControlTemplate>();
        
        foreach (string SingleItem in Items)
        {
            AzureItemControlTemplate SingleControl = new AzureItemControlTemplate(SingleItem, showDelete: false);
            
            Result.Add(SingleControl);
        }

        return Result;
    }

    internal async Task OpenUrlInBrowser(Uri url)
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;
        ILauncher Launcher = TopLevel.GetTopLevel(MainWindow).Launcher;
        await Launcher.LaunchUriAsync(url);
    }

    internal async Task<IReadOnlyList<IStorageFile>> GetIStorageFileListForOpenFile()
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;

        IReadOnlyList<IStorageFile> OpenFile = await MainWindow.StorageProvider.OpenFilePickerAsync(CreateFilePickerOpenOptions());
        
        return OpenFile;
    }
    
    internal async Task<IStorageFile> GetIStorageFileListForCreateFile()
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
        Window MainWindow = AppLifeTime.MainWindow;

        IStorageFile SaveFile = await MainWindow.StorageProvider.SaveFilePickerAsync(CreateFilePickerSaveOptions());
        
        return SaveFile;
    }
    
    internal FilePickerOpenOptions CreateFilePickerOpenOptions()
    {
        
        return new FilePickerOpenOptions()
        {
            Title = Strings.Azure_LoadFile_Title,
            AllowMultiple = false,
            FileTypeFilter = new List<FilePickerFileType>()
            {
                new FilePickerFileType(_filePickerDisplayName)
                {
                    Patterns = new List<string>()
                    {
                        _filePickerFilter
                    },
                    AppleUniformTypeIdentifiers = new List<string>()
                    {
                        _fileAppleIdentifier
                    },
                    MimeTypes = new List<string>()
                    {
                        _fileMimeType
                    }
                }
            }
        };
    }
    internal FilePickerSaveOptions CreateFilePickerSaveOptions()
    {
        return new FilePickerSaveOptions()
        {
            Title = Strings.AzureMFA_SaveFile_Title,
            FileTypeChoices = new List<FilePickerFileType>()
            {
                new FilePickerFileType(_filePickerDisplayName)
                {
                    Patterns = new List<string>()
                    {
                        _filePickerFilter
                    },
                    AppleUniformTypeIdentifiers = new List<string>()
                    {
                        _fileAppleIdentifier
                    },
                    MimeTypes = new List<string>()
                    {
                        _fileMimeType
                    }
                }
            },
            ShowOverwritePrompt = true,
            SuggestedFileName = $"{_fileNamePrefix}{DateTimeOffset.Now.ToString(_dateFormat)}{_fileNameSuffix}",
        };
    }
    
    internal string[] GetContentFromObservableCollection(ObservableCollection<AzureItemControlTemplate> Collection)
    {
        List<string> Groups = new List<string>();

        foreach (AzureItemControlTemplate SingleEntry in Collection)
        {
            if (SingleEntry.Label is not null)
            {
                Groups.Add(SingleEntry.Label);
            }
        }

        return Groups.ToArray();
    }
}