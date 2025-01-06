using Serilog.Core;
using System.CommandLine;
using System.CommandLine.Parsing;
using IRH.Remote.Commands.UploadFile;
using IRH.Remote.Commands.DownloadFile;

namespace IRH.Remote
{
    public class RemoteExecution
    {
        private const string _commandName = "-R";
        private const string _commandDescription = "All available Remote Commands";

        private readonly Logger _logger;

        public RemoteExecution(Logger Logger)
        {
            _logger = Logger;
        }

        public Command CreateCommand(RootCommand Root)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            UploadFile UploadFile = new UploadFile(_logger);
            Command UploadFileCommand = UploadFile.CreateCommand(Command);

            DownloadFile DownloadFile = new DownloadFile(_logger);
            Command DownloadFileCommand = DownloadFile.CreateCommand(Command);

            Command.AddCommand(UploadFileCommand);
            Command.AddCommand(DownloadFileCommand);

            return Command;
        }
    }
}
