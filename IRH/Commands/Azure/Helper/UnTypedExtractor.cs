using Microsoft.Kiota.Abstractions.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace IRH.Commands.Azure.Helper
{
    internal class UnTypedExtractor
    {

        private const string _untypedStringValueProperty = "_value";
        internal static async Task<List<KeyValuePair<string, string>>> ExtractUntypedArray(UntypedArray Array)
        {
            IEnumerable<UntypedNode> Values = Array.GetValue();

            List<KeyValuePair<string, string>> Result = new List<KeyValuePair<string, string>>();

            foreach (UntypedNode SingleValue in Values)
            {
                Result.AddRange(await ExtractUnTypedObject(SingleValue as UntypedObject));
            }

            return Result;
        }

        internal static async Task<List<KeyValuePair<string, string>>> ExtractUnTypedObject(UntypedObject Object)
        {
            IDictionary<string, UntypedNode> Values = Object.GetValue();
            List<KeyValuePair<string,string>> Result = new List<KeyValuePair<string, string>>();
            
            foreach(KeyValuePair<string, UntypedNode> Pair in Values)
            {
                Result.Add(new KeyValuePair<string, string>(Pair.Key, await ExtractUnTypedString(Pair.Value)));
            }

            return Result;
        }

        internal static async Task<string> ExtractUnTypedString(UntypedNode Node)
        {
            FieldInfo FieldValue = Node.GetType().GetField(_untypedStringValueProperty, BindingFlags.NonPublic | BindingFlags.Instance);
            
            string Result = (string)FieldValue.GetValue(Node);
            return Result;
        }
    }
}
