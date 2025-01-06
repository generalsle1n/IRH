using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using Serilog.Core;

namespace IRH.Remote.Commands.General
{
    internal class PowershellHelper
    {
        private const string _scriptPath = "IRH.Remote.Commands.General.Static.CopyFileFromRegToDisk.txt";
        private const string _scriptReplaceToken = "xXKeyNameXx";

        internal static string CreateScriptToWriteFileFromRegistry(string RegistryValueName, Logger logger)
        {
            Assembly Assembly = Assembly.GetExecutingAssembly();
            using (Stream Stream = Assembly.GetManifestResourceStream(_scriptPath))
            using (StreamReader Reader = new StreamReader(Stream))
            {
                string Script = Reader.ReadToEnd();
                logger.Information($"Creating Script to write file for {RegistryValueName}");
                Script = Script.Replace(_scriptReplaceToken, RegistryValueName);
                byte[] RawData = Encoding.Unicode.GetBytes(Script);
                return Convert.ToBase64String(RawData);
            }
        }
    }
}
