﻿using System;
using Asn1;
using System.Collections.Generic;
using System.Text;

namespace IRH.Kerberos
{
    public class KRB_ERROR
    {

        public KRB_ERROR(byte[] errorBytes)
        {

        }

        public KRB_ERROR(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        pvno = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        msg_type = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        ctime = s.Sub[0].GetTime();
                        break;
                    case 3:
                        cusec = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 4:
                        stime = s.Sub[0].GetTime();
                        break;
                    case 5:
                        susec = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 6:
                        error_code = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 7:
                        crealm = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 8:
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 9:
                        realm = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 10:
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    case 11:
                        e_text = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 12:
                        try
                        {
                            e_data = new List<PA_DATA>();
                            AsnElt tmpData = AsnElt.Decode(s.Sub[0].GetOctetString());
                            foreach (AsnElt tmp in tmpData.Sub)
                            {
                                e_data.Add(new PA_DATA(tmp));
                            }
                        }
                        catch (NullReferenceException)
                        {
                            e_data = null;
                        }
                        break;
                    default:
                        break;
                }
            }
        }


        public long pvno { get; set; }

        public long msg_type { get; set; }

        public DateTime ctime { get; set; }

        public long cusec { get; set; }

        public DateTime stime { get; set; }

        public long susec { get; set; }

        public long error_code { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public string e_text { get; set; }

        public List<PA_DATA> e_data { get; set; }

        public List<Ticket> tickets { get; set; }

        public EncKrbCredPart enc_part { get; set; }
    }
}