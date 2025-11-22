using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IRH.Commands.Deployment.Esxi;
using Serilog.Core;

namespace IRH.Commands.Deployment
{
    internal class DeploymentFunctions
    {
        private const string CommandName = "-D";
        private const string CommandDescription = "All deployment Commands";
        private const string CommandAlias = "--Deploy";

        private readonly Logger _logger;

        internal DeploymentFunctions(Logger Logger)
        {
            _logger = Logger;
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: CommandName, description: CommandDescription)
            {
                Aliases = {
                    CommandAlias
                }
            };

            EsxiDeploymentCommand EsxiDeploymentCommand = new EsxiDeploymentCommand(_logger);
            Command EsxiDeployment = EsxiDeploymentCommand.CreateCommand(RootCommand);

            Command.Add(EsxiDeployment);

            return Command;
        }
    }
}
