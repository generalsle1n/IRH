using IRH.Commands.Azure.MFA;
using IRH.Commands.Azure.AuditLog;
using IRH.Commands.LDAPMonitor;
using IRH.Commands.SetupDeployment;
using Serilog;
using Serilog.Core;
using System.CommandLine;

const string _commandDescription = "suite of some little helper tools within incident response when dealing with security breaches. These tools provide essential features for IT security professionals, making it easier to manage and respond to incidents effectively.";

Logger Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .MinimumLevel.Verbose()
    .CreateLogger();

RootCommand RootCommand = new RootCommand(_commandDescription);

LDAPMonitor LM = new LDAPMonitor(Logger);
SetupDeployment SD = new SetupDeployment(Logger);
AzureMFA AMFA = new AzureMFA(Logger);
AzureAuditLog AAudit = new AzureAuditLog(Logger);

Command LdapMonitor = LM.CreateCommand(RootCommand);
Command SetupDeployment = SD.CreateCommand(RootCommand);
Command AzureMFA = AMFA.CreateCommand(RootCommand);
Command AzureAuditLog = AAudit.CreateCommand(RootCommand);

RootCommand.AddCommand(LdapMonitor);
RootCommand.AddCommand(SetupDeployment);
RootCommand.AddCommand(AzureMFA);
RootCommand.AddCommand(AzureAuditLog);

await RootCommand.InvokeAsync(args);