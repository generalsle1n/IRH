﻿using Asn1;
using System;
using System.Text;

namespace IRH.Kerberos
{
    public class PA_KEY_LIST_REP
    {
        public PA_KEY_LIST_REP()
        {
            encryptionKey = new EncryptionKey();
        }
        public PA_KEY_LIST_REP(AsnElt body)
        {
            encryptionKey = new EncryptionKey(body);
        }

        public EncryptionKey encryptionKey { get; set; }

    }
}