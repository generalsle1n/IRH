//using IRH.Commands.Azure.MFA;
using IRH.Commands.Azure.AuditLog;
using IRH.Commands.LDAPMonitor;
using Serilog;
using Serilog.Core;
using System.CommandLine;
using IRH.Commands.Azure;
using IRH.Commands.Remote;
using IRH.Commands.Deployment;

const string _commandDescription = "suite of some little helper tools within incident response when dealing with security breaches. These tools provide essential features for IT security professionals, making it easier to manage and respond to incidents effectively.";

Logger Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .MinimumLevel.Information()
    .CreateLogger();

RootCommand RootCommand = new RootCommand(_commandDescription);

LDAPMonitor LM = new LDAPMonitor(Logger);
RemoteFunctions RM = new RemoteFunctions(Logger);
AzureFunctions AF = new AzureFunctions(Logger);
DeploymentFunctions DF = new DeploymentFunctions(Logger);

Command LdapMonitor = LM.CreateCommand(RootCommand);
Command RemoteFunction = RM.CreateCommand(RootCommand);
Command AzureFunctions = AF.CreateCommand(RootCommand);
Command DeploymentFunctions = DF.CreateCommand(RootCommand);

RootCommand.Subcommands.Add(LdapMonitor);
RootCommand.Subcommands.Add(RemoteFunction);
RootCommand.Subcommands.Add(AzureFunctions);
RootCommand.Subcommands.Add(DeploymentFunctions);

ParseResult result = RootCommand.Parse(args);
await result.InvokeAsync();