using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Asn1
{

    public static class AsnIO
    {

        public static byte[] FindDER(byte[] buf)
        {
            return FindBER(buf, true);
        }

        public static byte[] FindBER(byte[] buf)
        {
            return FindBER(buf, false);
        }

        public static byte[] FindBER(byte[] buf, bool strictDER)
        {
            string pemType = null;
            return FindBER(buf, strictDER, out pemType);
        }

        public static byte[] FindBER(byte[] buf, bool strictDER, out string pemType)
        {
            pemType = null;

            if (LooksLikeBER(buf, strictDER))
            {
                return buf;
            }

            if (buf.Length < 3)
            {
                return null;
            }
            string str = null;
            if ((buf.Length & 1) == 0)
            {
                if (buf[0] == 0xFE && buf[1] == 0xFF)
                {
                    str = ConvertBi(buf, 2, true);
                }
                else if (buf[0] == 0xFF && buf[1] == 0xFE)
                {
                    str = ConvertBi(buf, 2, false);
                }
                else if (buf[0] == 0)
                {
                    str = ConvertBi(buf, 0, true);
                }
                else if (buf[1] == 0)
                {
                    str = ConvertBi(buf, 0, false);
                }
            }
            if (str == null)
            {
                if (buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
                {
                    str = ConvertMono(buf, 3);
                }
                else
                {
                    str = ConvertMono(buf, 0);
                }
            }
            if (str == null)
            {
                return null;
            }

            int p = str.IndexOf("-----BEGIN ");
            int q = str.IndexOf("-----END ");
            if (p >= 0 && q >= 0)
            {
                p += 11;
                int r = str.IndexOf((char)10, p) + 1;
                int px = str.IndexOf('-', p);
                if (px > 0 && px < r && r > 0 && r <= q)
                {
                    pemType = string.Copy(str.Substring(p, px - p));
                    str = str.Substring(r, q - r);
                }
            }

            try
            {
                buf = Convert.FromBase64String(str);
                if (LooksLikeBER(buf, strictDER))
                {
                    return buf;
                }
            }
            catch
            {
            }

            return null;
        }

        static bool DecodeTag(byte[] buf, int lim, ref int off)
        {
            int p = off;
            if (p >= lim)
            {
                return false;
            }
            int v = buf[p++];
            if ((v & 0x1F) == 0x1F)
            {
                do
                {
                    if (p >= lim)
                    {
                        return false;
                    }
                    v = buf[p++];
                } while ((v & 0x80) != 0);
            }
            off = p;
            return true;
        }

        static int DecodeLength(byte[] buf, int lim, ref int off)
        {
            int p = off;
            if (p >= lim)
            {
                return -2;
            }
            int v = buf[p++];
            if (v < 0x80)
            {
                off = p;
                return v;
            }
            else if (v == 0x80)
            {
                off = p;
                return -1;
            }
            v &= 0x7F;
            if ((lim - p) < v)
            {
                return -2;
            }
            int acc = 0;
            while (v-- > 0)
            {
                if (acc > 0x7FFFFF)
                {
                    return -2;
                }
                acc = (acc << 8) + buf[p++];
            }
            off = p;
            return acc;
        }

        static int BERLength(byte[] buf, int lim, int off)
        {
            int orig = off;
            if (!DecodeTag(buf, lim, ref off))
            {
                return -1;
            }
            int len = DecodeLength(buf, lim, ref off);
            if (len >= 0)
            {
                if (len > (lim - off))
                {
                    return -1;
                }
                return off + len - orig;
            }
            else if (len < -1)
            {
                return -1;
            }

            for (; ; )
            {
                int slen = BERLength(buf, lim, off);
                if (slen < 0)
                {
                    return -1;
                }
                off += slen;
                if (slen == 2 && buf[off] == 0)
                {
                    return off - orig;
                }
            }
        }

        static bool LooksLikeBER(byte[] buf, bool strictDER)
        {
            return LooksLikeBER(buf, 0, buf.Length, strictDER);
        }

        static bool LooksLikeBER(byte[] buf, int off, int len, bool strictDER)
        {
            int lim = off + len;
            int objLen = BERLength(buf, lim, off);
            if (objLen != len)
            {
                return false;
            }
            if (strictDER)
            {
                DecodeTag(buf, lim, ref off);
                return DecodeLength(buf, lim, ref off) >= 0;
            }
            else
            {
                return true;
            }
        }

        static string ConvertMono(byte[] buf, int off)
        {
            int len = buf.Length - off;
            char[] tc = new char[len];
            for (int i = 0; i < len; i++)
            {
                int v = buf[off + i];
                if (v < 1 || v > 126)
                {
                    v = '?';
                }
                tc[i] = (char)v;
            }
            return new string(tc);
        }

        static string ConvertBi(byte[] buf, int off, bool be)
        {
            int len = buf.Length - off;
            if ((len & 1) != 0)
            {
                return null;
            }
            len >>= 1;
            char[] tc = new char[len];
            for (int i = 0; i < len; i++)
            {
                int b0 = buf[off + (i << 1) + 0];
                int b1 = buf[off + (i << 1) + 1];
                int v = be ? ((b0 << 8) + b1) : (b0 + (b1 << 8));
                if (v < 1 || v > 126)
                {
                    v = '?';
                }
                tc[i] = (char)v;
            }
            return new string(tc);
        }
    }
}
