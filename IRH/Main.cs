using IRH.Commands.Azure.MFA;
using IRH.Commands.Azure.AuditLog;
using IRH.Commands.LDAPMonitor;
using Serilog;
using Serilog.Core;
using System.CommandLine;
using IRH.Commands.Azure;
using IRH.Remote;

const string _commandDescription = "suite of some little helper tools within incident response when dealing with security breaches. These tools provide essential features for IT security professionals, making it easier to manage and respond to incidents effectively.";

Logger Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .MinimumLevel.Information()
    .CreateLogger();

RootCommand RootCommand = new RootCommand(_commandDescription);

LDAPMonitor LM = new LDAPMonitor(Logger);
RemoteExecution RM = new RemoteExecution(Logger);
AzureFunctions AF = new AzureFunctions(Logger);

Command LdapMonitor = LM.CreateCommand(RootCommand);
Command RemoteExecution = RM.CreateCommand(RootCommand);
Command AzureFunctions = AF.CreateCommand(RootCommand);

RootCommand.AddCommand(LdapMonitor);
RootCommand.AddCommand(RemoteExecution);
RootCommand.AddCommand(AzureFunctions);

await RootCommand.InvokeAsync(args);