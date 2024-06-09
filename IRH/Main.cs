using IRH.Commands.LDAPMonitor;
using IRH.Commands.SetupDeployment;
using Serilog;
using Serilog.Core;
using System.CommandLine;

Logger Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .MinimumLevel.Verbose()
    .CreateLogger();

RootCommand RootCommand = new RootCommand();

LDAPMonitor LM = new LDAPMonitor(Logger);
SetupDeployment SD = new SetupDeployment();

Command LdapMonitor = LM.CreateCommand(RootCommand);
Command SetupDeployment = SD.CreateCommand(RootCommand);

RootCommand.AddCommand(LdapMonitor);
RootCommand.AddCommand(SetupDeployment);

await RootCommand.InvokeAsync(args);