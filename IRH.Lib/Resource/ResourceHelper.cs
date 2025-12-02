using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Lib.Resource
{
    internal class ResourceHelper
    {
        internal static string GetResourceString(string resourceName)
        {
            Assembly currentAssembly = typeof(ResourceHelper).Assembly;
            
            using(Stream stream = currentAssembly.GetManifestResourceStream(resourceName))
            using(StreamReader streamReader = new StreamReader(stream))
            {
                return streamReader.ReadToEnd();
            }
        }
    }
}
