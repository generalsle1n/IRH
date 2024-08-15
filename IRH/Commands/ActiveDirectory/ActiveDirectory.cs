using Serilog.Core;
using System.CommandLine;
using Serilog.Core;
using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;

namespace IRH.Commands.ActiveDirectory
{
    internal class ActiveDirectory
    {
        private const string _commandName = "-AD";
        private const string _commandDescription = "All Active Directory related Options";

        private readonly Logger _logger;

        internal ActiveDirectory(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            
            Command.SetHandler(() =>
            {
                var a = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)
                {
                    
                };

                var b = CSharpCompilation.Create("lol", options: a);
                b.Emit(@"C:\temp\lol.dll");
            });

            return Command;
        }
    }
}
