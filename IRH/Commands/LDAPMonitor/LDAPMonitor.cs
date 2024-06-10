using Serilog.Core;
using System.CommandLine;
using System.DirectoryServices.Protocols;
using System.Net;

namespace IRH.Commands.LDAPMonitor
{
    internal class LDAPMonitor
    {
        private const string _commandName = "-LS";
        private const string _commandDescription = "Scan an Ldap Path for changes";

        private const string _domainName = "-N";
        private const string _domainDescription = "Enter the Name for the Domain";
        private const string _domainNameAlias = "--Name";
        private const bool _domainIsRequired = true;

        private const string _userName = "-U";
        private const string _userDescription = "Enter the Username to connect";
        private const string _userNameAlias = "--User";
        private const bool _userIsRequired = true;

        private const string _passwordName = "-P";
        private const string _passwordDescription = "Enter the password from the user";
        private const string _passwordNameAlias = "--Password";
        private const bool _passwordIsRequired = true;

        private const string _portName = "-p";
        private const string _portDescription = "To change the default ldap Prt";
        private const string _portNameAlias = "--Port";
        private const int _portDefaultValue = 389;

        private const string _ldapMatchAll = "(&(objectClass=*))";
        private const string _rootDSEAttribute = "rootdomainnamingcontext";

        private readonly Logger _logger;
        private LdapConnection _connection;

        private event EventHandler<LDAPChangeEvent> _objectChangeHandler;

        internal LDAPMonitor(Logger Logger)
        {
            _logger = Logger;
        }

        private void RegisterLdap(string Server, int Port, string Username, string Password)
        {
            LdapDirectoryIdentifier Identifier = new LdapDirectoryIdentifier(Server, Port);
            NetworkCredential Credential = new NetworkCredential(Username, Password);

            _logger.Debug($"Create Connection to {Server}:{Port} with {Username}");
            _connection = new LdapConnection(Identifier, Credential);
            try
            {
                _logger.Information($"Try to Conect to {Server}:{Port} with {Username}");
                _connection.Bind();
                _logger.Information($"Connected to Server");
            }
            catch (LdapException e)
            {
                _logger.Fatal($"{e.Message} (Bind Data {Server}:{Port})");
            }
            _connection.Bind();
        }

        private string GetDSNRoot()
        {
            SearchRequest Request = new SearchRequest(null, _ldapMatchAll, SearchScope.Base, null);
            SearchResponse Response = (SearchResponse)_connection.SendRequest(Request);
            DirectoryAttribute RootDomain = Response.Entries[0].Attributes[_rootDSEAttribute];
            string DNRoot = (string)RootDomain.GetValues(typeof(string))[0];

            return DNRoot;
        }

        private void CreateMonitor(string DN)
        {
            RegisterLdapEvent(DN);

            _objectChangeHandler += new EventHandler<LDAPChangeEvent>(ProcessLdapEvent);

            Console.WriteLine("Waiting for changes...");
            Console.WriteLine();
            Console.ReadLine();
        }

        private void RegisterLdapEvent(string DN)
        {
            SearchRequest Request = new SearchRequest(DN, _ldapMatchAll, SearchScope.Subtree, null);
            Request.Controls.Add(new DirectoryNotificationControl());

            IAsyncResult Result = _connection.BeginSendRequest(Request, TimeSpan.FromDays(1), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, LdapEventNotifier, Request);
        }

        private void LdapEventNotifier(IAsyncResult Result)
        {
            PartialResultsCollection ResultCollection = _connection.GetPartialResults(Result);

            foreach (SearchResultEntry Entry in ResultCollection)
            {
                LDAPOnChangeObject(new LDAPChangeEvent(Entry));
            }
        }

        private void LDAPOnChangeObject(LDAPChangeEvent Args)
        {
            if (_objectChangeHandler != null)
            {
                _objectChangeHandler(this, Args);
            }
        }

        private void ProcessLdapEvent(object sender, LDAPChangeEvent Event)
        {
            _logger.Information($"Action on {Event.Result.DistinguishedName}");

            foreach (string Attribute in Event.Result.Attributes.AttributeNames)
            {
                foreach (string Value in Event.Result.Attributes[Attribute].GetValues(typeof(string)))
                {
                    _logger.Information($"| | | {Attribute}:{Value}");
                }
            }

            _logger.Information("-----------------------------------------");
        }

        internal Command CreateCommand(RootCommand RootCommand)
        {
            Command Command = new Command(name: _commandName, description: _commandDescription);

            Option<string> Domain = new Option<string>(name: _domainName, description: _domainDescription);
            Option<string> Username = new Option<string>(name: _userName, description: _userDescription);
            Option<string> Password = new Option<string>(name: _passwordName, description: _passwordDescription);
            Option<int> Port = new Option<int>(name: _portName, description: _portDescription);

            Domain.AddAlias(_domainNameAlias);
            Username.AddAlias(_userNameAlias);
            Password.AddAlias(_passwordNameAlias);
            Port.AddAlias(_portNameAlias);

            Domain.IsRequired = _domainIsRequired;
            Username.IsRequired = _userIsRequired;
            Password.IsRequired = _passwordIsRequired;

            Port.SetDefaultValue(_portDefaultValue);

            Command.AddOption(Domain);
            Command.AddOption(Username);
            Command.AddOption(Password);
            Command.AddOption(Port);

            Command.SetHandler((DomainValue, UsernameValue, PasswordValue, PortValue) =>
            {
                RegisterLdap(DomainValue, PortValue, UsernameValue, PasswordValue);

                string RootDN = GetDSNRoot();
                _logger.Information($"Root DN found: {RootDN}");

                CreateMonitor(RootDN);
                Console.ReadLine();

            }, Domain, Username, Password, Port);

            return Command;
        }
    }
}
