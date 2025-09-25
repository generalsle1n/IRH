using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using IRH.Ui.Models.Azure;
using IRH.Ui.Resources;

namespace IRH.Ui.Lib;

public class UiHelper
{
    internal async Task SetTextToClipboard(string text)
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current!.ApplicationLifetime!;
        Window MainWindow = AppLifeTime.MainWindow!;
        IClipboard Clipboard = MainWindow.Clipboard!;

        await Clipboard.SetTextAsync(text);
    }

    internal static ObservableCollection<AzureItemControlTemplate> CreateObservableItemControlTemplateFromList(List<string> items)
    {
        ObservableCollection<AzureItemControlTemplate> Result = new ObservableCollection<AzureItemControlTemplate>();
        
        foreach (string SingleItem in items)
        {
            AzureItemControlTemplate SingleControl = new AzureItemControlTemplate(SingleItem, showDelete: false);
            
            Result.Add(SingleControl);
        }

        return Result;
    }

    internal async Task OpenUrlInBrowserAsync(Uri url)
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current!.ApplicationLifetime!;
        Window MainWindow = AppLifeTime.MainWindow!;
        ILauncher Launcher = TopLevel.GetTopLevel(MainWindow)!.Launcher;
        await Launcher.LaunchUriAsync(url);
    }

    internal async Task<IReadOnlyList<IStorageFile>> GetIStorageFileListForOpenFile()
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current!.ApplicationLifetime!;
        Window MainWindow = AppLifeTime.MainWindow!;

        IReadOnlyList<IStorageFile> OpenFile = await MainWindow.StorageProvider.OpenFilePickerAsync(CreateFilePickerOpenOptions());
        
        return OpenFile;
    }
    
    internal async Task<IStorageFile> GetIStorageFileListForCreateFile()
    {
        IClassicDesktopStyleApplicationLifetime AppLifeTime = (IClassicDesktopStyleApplicationLifetime)Application.Current!.ApplicationLifetime!;
        Window MainWindow = AppLifeTime.MainWindow!;

        IStorageFile SaveFile = (await MainWindow.StorageProvider.SaveFilePickerAsync(CreateFilePickerSaveOptions()))!;
        
        return SaveFile;
    }
    
    private FilePickerOpenOptions CreateFilePickerOpenOptions()
    {
        
        return new FilePickerOpenOptions()
        {
            Title = Strings.Azure_LoadFile_Title,
            AllowMultiple = false,
            FileTypeFilter = new List<FilePickerFileType>()
            {
                new FilePickerFileType(DefaultUiValue.FilePickerDisplayName)
                {
                    Patterns = new List<string>()
                    {
                        DefaultUiValue.FilePickerFilter
                    },
                    AppleUniformTypeIdentifiers = new List<string>()
                    {
                        DefaultUiValue.FileAppleIdentifier
                    },
                    MimeTypes = new List<string>()
                    {
                        DefaultUiValue.FileMimeType
                    }
                }
            }
        };
    }
    private FilePickerSaveOptions CreateFilePickerSaveOptions()
    {
        return new FilePickerSaveOptions()
        {
            Title = Strings.AzureMFA_SaveFile_Title,
            FileTypeChoices = new List<FilePickerFileType>()
            {
                new FilePickerFileType(DefaultUiValue.FilePickerDisplayName)
                {
                    Patterns = new List<string>()
                    {
                        _filePickerFilter
                    },
                    AppleUniformTypeIdentifiers = new List<string>()
                    {
                        DefaultUiValue.FileAppleIdentifier
                    },
                    MimeTypes = new List<string>()
                    {
                        DefaultUiValue.FileMimeType
                    }
                }
            },
            ShowOverwritePrompt = true,
            SuggestedFileName = $"{DefaultUiValue.FileNamePrefix}{DateTimeOffset.Now.ToString(DefaultUiValue.DateFormat)}{DefaultUiValue.FileNameSuffix}",
        };
    }
    
    internal string[] GetContentFromObservableCollection(ObservableCollection<AzureItemControlTemplate> collection)
    {
        List<string> Groups = new List<string>();

        foreach (AzureItemControlTemplate SingleEntry in collection)
        {
            Groups.Add(SingleEntry.Label);
        }

        return Groups.ToArray();
    }
}