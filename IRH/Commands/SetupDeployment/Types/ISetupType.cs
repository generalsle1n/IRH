using Serilog.Core;

namespace IRH.Commands.SetupDeployment.Types
{
    public interface ISetupType
    {
        public string SourceBinary { get; set; }
        public string Parameters { get; set; }
        public string DestinationPC { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }

        public Logger Logger { get; set; }

        public bool Install();
    }
}
