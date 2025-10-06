using System.CommandLine;
using System.Net;
using IRH.Lib;
using IRH.Lib.Class.Remote.CopyFile;
using IRH.Lib.Model.Remote.CopyFile;
using Serilog.Core;

namespace IRH.Commands.Remote.CopyFile;

internal class CopyFileToRemoteCommand
{
    private const string CommandName = "-CR";
    private const string CommandDescription = "Copy an File to a Remote System";
    private const string CommandAlias = "--CopyRemote";
    
    private const string CopyTypeName = "-T";
    private const string CopyTypeDescription = "Configure the copy type which should be used to transfer the file";
    private const string CopyTypeAlias = "--Type";
    private readonly CopyType CopyTypeDefaultValue = DefaultValue.CopyType;
    
    private const string ShareNameName = "-S";
    private const string ShareNameDescription = "Set the Sharename e.g. C$";
    private const string ShareNameAlias = "--Share";
    private const bool ShareNameIsRequired = true;
    
    private const string SourceFileName = "-SF";
    private const string SourceFileDescription = "Enter the Source File which should be copied";
    private const string SourceFileAlias = "--SourceFile";
    private const bool SourceFileIsRequired = true;
    
    private const string DestinationFileName = "-DF";
    private const string DestinationFileDescription = @"Enter the Destination Path where the File should be placed without volume prefix (The path need to be an Folder, when you want to Copy the file to C:\temp\testFile.exe then you need to enter temp\testFile.exe)";
    private const string DestinationFileAlias = "--DestinationFile";
    private const bool DestinationFileIsRequired = true;
    
    private readonly Logger _logger;

    internal CopyFileToRemoteCommand(Logger Logger)
    {
        _logger = Logger;
    }
    
    internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: CommandName, description: CommandDescription)
            {
                Aliases =
                {
                    CommandAlias
                }
            };
            
            Option<CopyType> CopyTypeOption = new Option<CopyType>(name: CopyTypeName, aliases: CopyTypeAlias)
            {
                Description = CopyTypeDescription,
                DefaultValueFactory = (result) => CopyTypeDefaultValue
            };
            
            Option<string> ShareNameOption = new Option<string>(name: ShareNameName, aliases: ShareNameAlias)
            {
                Description = ShareNameDescription,
                Required = ShareNameIsRequired
            };
            
            Option<FileInfo> SourceFileOption = new Option<FileInfo>(name: SourceFileName, aliases: SourceFileAlias)
            {
                Description = SourceFileDescription,
                Required = SourceFileIsRequired
            };
            
            Option<string> DestinationFileOption = new Option<string>(name: DestinationFileName, aliases: DestinationFileAlias)
            {
                Description = DestinationFileDescription,
                Required = DestinationFileIsRequired
            };
            
            Command.Options.Add(CopyTypeOption);
            Command.Options.Add(ShareNameOption);
            Command.Options.Add(SourceFileOption);
            Command.Options.Add(DestinationFileOption);
            
            Command.SetAction(async parseResult =>
            {
                FileInfo SourceFile = parseResult.GetRequiredValue<FileInfo>(SourceFileOption);

                byte[] FileData = await File.ReadAllBytesAsync(SourceFile.FullName);
                
                CopyFileToRemote CopyFileToRemoteCommand = new CopyFileToRemote(_logger);
                
                string[] AllServers = parseResult.GetRequiredValue<string[]>(RemoteFunctions.RemoteServerName);
                
                _logger.Information($"Found Remote Devices: {AllServers.Length}");

                List<Task> AllCopyTasks = new List<Task>();
                
                foreach (string SingleServer in AllServers)
                {
                    Task SingleCopyTask = CopyFileToRemoteCommand.CopySingleFileAsync(
                        parseResult.GetRequiredValue<CopyType>(CopyTypeOption),
                        parseResult.GetRequiredValue<string>(RemoteFunctions.UserNameName),
                        parseResult.GetRequiredValue<string>(RemoteFunctions.PasswordName),
                        parseResult.GetRequiredValue<string>(RemoteFunctions.DomainName),
                        FileData,
                        SingleServer,
                        parseResult.GetRequiredValue<string>(ShareNameOption),
                        parseResult.GetRequiredValue<string>(DestinationFileOption));
                    
                    AllCopyTasks.Add(SingleCopyTask);
                }
                
                await Task.WhenAll(AllCopyTasks);
                
            });

            return Command;
        }
}