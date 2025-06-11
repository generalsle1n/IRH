using IRH.Lib;
using IRH.Lib.Model.Azure.Auth;
using IRH.Lib.Model.General;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IRH.UI.Custom
{
    internal class PreferenceHelper
    {
        internal const string DefaultTenantIDName = "TenantIDSetting";
        internal const string DefaultAppIDName = "AppIDSetting";
        internal const string DefaultAuthTypeName = "AuthTypeSetting";
        internal const string DefaultLanguageName = "LanguageSetting";

        internal static void LoadInitData(bool Reset = false)
        {
            if (!Preferences.ContainsKey(DefaultTenantIDName) || Reset)
            {
                Preferences.Set(DefaultTenantIDName, DefaultValue.TenantID);
            }

            if (!Preferences.ContainsKey(DefaultAppIDName) || Reset)
            {
                Preferences.Set(DefaultAppIDName, DefaultValue.AppID);
            }

            if (!Preferences.ContainsKey(DefaultAuthTypeName) || Reset)
            {
                Preferences.Set(DefaultAuthTypeName, GetIndexFromEnum<AuthType>(DefaultValue.AuthType));
            }

            if (!Preferences.ContainsKey(DefaultLanguageName) || Reset)
            {
                Preferences.Set(DefaultLanguageName, GetIndexFromEnum<Language>(Language.DE));
            }
        }

        internal static int GetIndexFromEnum<T>(T EnumValue) where T : Enum
        {
            Array EnumValuesArray = Enum.GetValues(typeof(T));
            int Result = Array.IndexOf(EnumValuesArray, EnumValue);
            return Result;
        }

        internal static T GetEnumFromIndex<T>(int Index) where T : Enum
        {
            T EnumValue = (T)Enum.Parse(typeof(T), Index.ToString());
            return EnumValue;
        }
    }
}
