using Microsoft.Graph.Beta.Models.Security;
using Microsoft.Kiota.Abstractions.Serialization;
using System.Reflection;

namespace IRH.Commands.Azure.Helper
{
    internal class UnTypedExtractor
    {
        internal static async Task<List<KeyValuePair<string, string>>> ExtractUntypedDataFromAuditLogRecord(AuditLogRecord Record)
        {
            IEnumerable<KeyValuePair<string,object>> Types = Record.AuditData.AdditionalData.Where(type => type.Value is UntypedArray || type.Value is UntypedObject);
            List<KeyValuePair<string, string>> Result = new List<KeyValuePair<string, string>>();

            foreach (KeyValuePair<string, object> SingleType in Types)
            {
                if (SingleType.Value is UntypedArray)
                {
                    Result.AddRange(await ExtractUntypedArray(SingleType.Value as UntypedArray));
                }
                else if(SingleType.Value is UntypedObject)
                {
                    Result.AddRange(await ExtractUnTypedObject(SingleType.Value as UntypedObject));
                }
            }

            return Result;
        }

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
                Result.Add(new KeyValuePair<string, string>(Pair.Key, await ExtractUntypeUnknownType(Pair.Value)));
            }

            return Result;
        }

        internal static async Task<string> ExtractUntypeUnknownType(UntypedNode Node)
        {
            string Result = null;

            switch (Node)
            {
                case UntypedString:
                    Result = await ExtractUnTypedString(Node);
                    break;
                case UntypedInteger:
                    Result = await ExtractUnTypedInteger(Node);
                    break;
                case UntypedBoolean:
                    Result = await ExtractUnTypedBoolean(Node);
                    break;
                case UntypedDecimal:
                    Result = await ExtractUnTypedDecimal(Node);
                    break;
                case UntypedDouble:
                    Result = await ExtractUnTypedDouble(Node);
                    break;
                case UntypedFloat:
                    Result = await ExtractUnTypedFloat(Node);
                    break;
                case UntypedLong:
                    Result = await ExtractUnTypedLong(Node);
                    break;
                case UntypedNull:
                    Result = await ExtractUnTypedNull(Node);
                    break;
            }

            return Result;
        }

        internal static async Task<string> ExtractUnTypedString(UntypedNode Node)
        {
            return (Node as UntypedString).GetValue();
        }
            
            string Result = (string)FieldValue.GetValue(Node);
            return Result;
        }
    }
}
