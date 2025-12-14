using System.CommandLine;
using IRH.Commands.Remote.CopyFile;
using Serilog.Core;

namespace IRH.Commands.Remote;

internal class RemoteFunctions
{
    private const string CommandName = "-R";
    private const string CommandDescription = "All remote Commands";
    private const string CommandAlias = "--Remote";

    internal const string UserNameName = "-U";
    private const string UserNameDescription = "Enter the Username to connect";
    private const string UserNameAlias = "--User";
    private const bool UserNameIsRequired = true;
    
    internal const string PasswordName = "-P";
    private const string PasswordDescription = "Enter the Password to connect";
    private const string PasswordAlias = "--Password";
    private const bool PaswordIsRequired = true;
    
    internal const string DomainName = "-D";
    private const string DomainDescription = "Enter the Domain to connect";
    private const string DomainAlias = "--Domain";
    private const bool DomainIsRequired = true;
    
    internal const string RemoteServerName = "-IP";
    private const string RemoteServerDescription = "Enter the Server (FQDN/IP) to connect (You can enter multiple Servers Seperated by a Space)";
    private const string RemoteServerAlias = "--Server";
    private const bool RemoteServerIsRequired = true;
    
    private readonly Logger _logger;

    internal RemoteFunctions(Logger Logger)
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

        Option<string> Username = new Option<string>(name: UserNameName, aliases: UserNameAlias)
        {
            Description = UserNameDescription,
            Required = UserNameIsRequired,
            Recursive = true
        };
        
        Option<string> Password = new Option<string>(name: PasswordName, aliases: PasswordAlias)
        {
            Description = PasswordDescription,
            Required = PaswordIsRequired,
            Recursive = true
        };
        
        Option<string> Domain = new Option<string>(name: DomainName, aliases: DomainAlias)
        {
            Description = DomainDescription,
            Required = DomainIsRequired,
            Recursive = true
        };
        
        Option<string[]> RemoteServer = new Option<string[]>(name: RemoteServerName, aliases: RemoteServerAlias)
        {
            Description = RemoteServerDescription,
            Required = RemoteServerIsRequired,
            AllowMultipleArgumentsPerToken = true,
            Recursive = true
        };
        
        Command.Options.Add(Username);
        Command.Options.Add(Password);
        Command.Options.Add(Domain);
        Command.Options.Add(RemoteServer);
        
        CopyFileToRemoteCommand CopyFileToRemoteCommand = new CopyFileToRemoteCommand(_logger);
        Command CopyFileToRemote = CopyFileToRemoteCommand.CreateCommand(RootCommand);

        Command.Add(CopyFileToRemote);
        
        return Command;
    }
}