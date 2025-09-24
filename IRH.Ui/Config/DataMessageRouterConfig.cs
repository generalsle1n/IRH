using System;
using System.Collections.Generic;
using IRH.Lib.Model.Azure.Mail;

namespace IRH.Ui.Config;

public class DataMessageRouterConfig
{
    public static List<string> Types { get; } = new List<string>()
    {
        "UserMailCollection"
    };
}