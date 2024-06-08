using IRH.Commands.LDAPMonitor;
using Serilog;
using Serilog.Core;
using System.CommandLine;

Logger Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .MinimumLevel.Verbose()
    .CreateLogger();

RootCommand RootCommand = new RootCommand();

LDAPMonitor LM = new LDAPMonitor(Logger);
Command LdapMonitor = LM.CreateCommand(RootCommand);

RootCommand.AddCommand(LdapMonitor);

await RootCommand.InvokeAsync(args);