﻿using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using IRH.Kerberos.Ndr;
using IRH.Kerberos.Win32.Rpc;

namespace IRH.Kerberos.Ndr
{

    #region Marshal Helpers
    internal class _Marshal_Helper : Marshal.NdrMarshalBuffer
    {
        public void Write_0(_PAC_DEVICE_INFO p0)
        {
            WriteStruct<_PAC_DEVICE_INFO>(p0);
        }
        public void Write_1(_RPC_SID p0)
        {
            WriteStruct<_RPC_SID>(p0);
        }
        public void Write_2(_RPC_SID_IDENTIFIER_AUTHORITY p0)
        {
            WriteStruct<_RPC_SID_IDENTIFIER_AUTHORITY>(p0);
        }
        public void Write_3(_GROUP_MEMBERSHIP p0)
        {
            WriteStruct<_GROUP_MEMBERSHIP>(p0);
        }
        public void Write_4(_KERB_SID_AND_ATTRIBUTES p0)
        {
            WriteStruct<_KERB_SID_AND_ATTRIBUTES>(p0);
        }
        public void Write_5(DOMAIN_GROUP_MEMBERSHIP p0)
        {
            WriteStruct<DOMAIN_GROUP_MEMBERSHIP>(p0);
        }
        public void Write_6(_PAC_DEVICE_CLAIMS_INFO p0)
        {
            WriteStruct<_PAC_DEVICE_CLAIMS_INFO>(p0);
        }
        public void Write_7(_CLAIMS_SET_METADATA p0)
        {
            WriteStruct<_CLAIMS_SET_METADATA>(p0);
        }
        public void Write_8(_UPN_DNS_INFO p0)
        {
            WriteStruct<_UPN_DNS_INFO>(p0);
        }
        public void Write_9(_KERB_VALIDATION_INFO p0)
        {
            WriteStruct<_KERB_VALIDATION_INFO>(p0);
        }
        public void Write_10(_RPC_UNICODE_STRING p0)
        {
            WriteStruct<_RPC_UNICODE_STRING>(p0);
        }
        public void Write_11(_USER_SESSION_KEY p0)
        {
            WriteStruct<_USER_SESSION_KEY>(p0);
        }
        public void Write_12(_CYPHER_BLOCK p0)
        {
            WriteStruct<_CYPHER_BLOCK>(p0);
        }
        public void Write_13(_PAC_INFO_BUFFER p0)
        {
            WriteStruct<_PAC_INFO_BUFFER>(p0);
        }
        public void Write_14(_NTLM_SUPPLEMENTAL_CREDENTIAL p0)
        {
            WriteStruct<_NTLM_SUPPLEMENTAL_CREDENTIAL>(p0);
        }
        public void Write_15(_PAC_CLIENT_INFO p0)
        {
            WriteStruct<_PAC_CLIENT_INFO>(p0);
        }
        public void Write_16(_S4U_DELEGATION_INFO p0)
        {
            WriteStruct<_S4U_DELEGATION_INFO>(p0);
        }
        public void Write_17(_PAC_CREDENTIAL_DATA p0)
        {
            WriteStruct<_PAC_CREDENTIAL_DATA>(p0);
        }
        public void Write_18(_SECPKG_SUPPLEMENTAL_CRED p0)
        {
            WriteStruct<_SECPKG_SUPPLEMENTAL_CRED>(p0);
        }
        public void Write_19(_GROUP_MEMBERSHIP[] p0, long p1)
        {
            WriteConformantStructArray<_GROUP_MEMBERSHIP>(p0, p1);
        }
        public void Write_20(_KERB_SID_AND_ATTRIBUTES[] p0, long p1)
        {
            WriteConformantStructArray<_KERB_SID_AND_ATTRIBUTES>(p0, p1);
        }
        public void Write_21(DOMAIN_GROUP_MEMBERSHIP[] p0, long p1)
        {
            WriteConformantStructArray<DOMAIN_GROUP_MEMBERSHIP>(p0, p1);
        }
        public void Write_22(int[] p0, long p1)
        {
            WriteConformantArray<int>(p0, p1);
        }
        public void Write_23(byte[] p0)
        {
            WriteFixedByteArray(p0, 6);
        }
        public void Write_24(_GROUP_MEMBERSHIP[] p0, long p1)
        {
            WriteConformantStructArray<_GROUP_MEMBERSHIP>(p0, p1);
        }
        public void Write_25(byte[] p0, long p1)
        {
            WriteConformantArray<byte>(p0, p1);
        }
        public void Write_26(byte[] p0, long p1)
        {
            WriteConformantArray<byte>(p0, p1);
        }
        public void Write_27(_GROUP_MEMBERSHIP[] p0, long p1)
        {
            WriteConformantStructArray<_GROUP_MEMBERSHIP>(p0, p1);
        }
        public void Write_28(int[] p0)
        {
            WriteFixedPrimitiveArray<int>(p0, 2);
        }
        public void Write_29(int[] p0)
        {
            WriteFixedPrimitiveArray<int>(p0, 7);
        }
        public void Write_30(_KERB_SID_AND_ATTRIBUTES[] p0, long p1)
        {
            WriteConformantStructArray<_KERB_SID_AND_ATTRIBUTES>(p0, p1);
        }
        public void Write_31(_GROUP_MEMBERSHIP[] p0, long p1)
        {
            WriteConformantStructArray<_GROUP_MEMBERSHIP>(p0, p1);
        }
        public void Write_32(char[] p0, long p1, long p2)
        {
            WriteConformantVaryingArray<char>(p0, p1, p2);
        }
        public void Write_33(_CYPHER_BLOCK[] p0)
        {
            WriteFixedStructArray<_CYPHER_BLOCK>(p0, 2);
        }
        public void Write_34(sbyte[] p0)
        {
            WriteFixedPrimitiveArray<sbyte>(p0, 8);
        }
        public void Write_35(sbyte[] p0)
        {
            WriteFixedPrimitiveArray<sbyte>(p0, 16);
        }
        public void Write_36(string p0)
        {
            WriteFixedString(p0, 1);
        }
        public void Write_37(_RPC_UNICODE_STRING[] p0, long p1)
        {
            WriteConformantStructArray<_RPC_UNICODE_STRING>(p0, p1);
        }
        public void Write_38(_SECPKG_SUPPLEMENTAL_CRED[] p0, long p1)
        {
            WriteConformantStructArray<_SECPKG_SUPPLEMENTAL_CRED>(p0, p1);
        }
        public void Write_39(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        internal void Write_40(_FILETIME p0)
        {
            WriteStruct<_FILETIME>(p0);
        }
    }
    internal class _Unmarshal_Helper : Marshal.NdrUnmarshalBuffer
    {

        public _Unmarshal_Helper(byte[] ba) :
                base(ba)
        {
        }
        public _PAC_DEVICE_INFO Read_0()
        {
            return ReadStruct<_PAC_DEVICE_INFO>();
        }
        public _RPC_SID Read_1()
        {
            return ReadStruct<_RPC_SID>();
        }
        public _RPC_SID_IDENTIFIER_AUTHORITY Read_2()
        {
            return ReadStruct<_RPC_SID_IDENTIFIER_AUTHORITY>();
        }
        public _GROUP_MEMBERSHIP Read_3()
        {
            return ReadStruct<_GROUP_MEMBERSHIP>();
        }
        public _KERB_SID_AND_ATTRIBUTES Read_4()
        {
            return ReadStruct<_KERB_SID_AND_ATTRIBUTES>();
        }
        public DOMAIN_GROUP_MEMBERSHIP Read_5()
        {
            return ReadStruct<DOMAIN_GROUP_MEMBERSHIP>();
        }
        public _PAC_DEVICE_CLAIMS_INFO Read_6()
        {
            return ReadStruct<_PAC_DEVICE_CLAIMS_INFO>();
        }
        public _CLAIMS_SET_METADATA Read_7()
        {
            return ReadStruct<_CLAIMS_SET_METADATA>();
        }
        public _UPN_DNS_INFO Read_8()
        {
            return ReadStruct<_UPN_DNS_INFO>();
        }
        public _KERB_VALIDATION_INFO Read_9()
        {
            return ReadStruct<_KERB_VALIDATION_INFO>();
        }
        public _RPC_UNICODE_STRING Read_10()
        {
            return ReadStruct<_RPC_UNICODE_STRING>();
        }
        public _USER_SESSION_KEY Read_11()
        {
            return ReadStruct<_USER_SESSION_KEY>();
        }
        public _CYPHER_BLOCK Read_12()
        {
            return ReadStruct<_CYPHER_BLOCK>();
        }
        public _PAC_INFO_BUFFER Read_13()
        {
            return ReadStruct<_PAC_INFO_BUFFER>();
        }
        public _NTLM_SUPPLEMENTAL_CREDENTIAL Read_14()
        {
            return ReadStruct<_NTLM_SUPPLEMENTAL_CREDENTIAL>();
        }
        public _PAC_CLIENT_INFO Read_15()
        {
            return ReadStruct<_PAC_CLIENT_INFO>();
        }
        public _S4U_DELEGATION_INFO Read_16()
        {
            return ReadStruct<_S4U_DELEGATION_INFO>();
        }
        public _PAC_CREDENTIAL_DATA Read_17()
        {
            return ReadStruct<_PAC_CREDENTIAL_DATA>();
        }
        public _SECPKG_SUPPLEMENTAL_CRED Read_18()
        {
            return ReadStruct<_SECPKG_SUPPLEMENTAL_CRED>();
        }
        public _GROUP_MEMBERSHIP[] Read_19()
        {
            return ReadConformantStructArray<_GROUP_MEMBERSHIP>();
        }
        public _KERB_SID_AND_ATTRIBUTES[] Read_20()
        {
            return ReadConformantStructArray<_KERB_SID_AND_ATTRIBUTES>();
        }
        public DOMAIN_GROUP_MEMBERSHIP[] Read_21()
        {
            return ReadConformantStructArray<DOMAIN_GROUP_MEMBERSHIP>();
        }
        public int[] Read_22()
        {
            return ReadConformantArray<int>();
        }
        public byte[] Read_23()
        {
            return ReadFixedByteArray(6);
        }
        public _GROUP_MEMBERSHIP[] Read_24()
        {
            return ReadConformantStructArray<_GROUP_MEMBERSHIP>();
        }
        public byte[] Read_25()
        {
            return ReadConformantArray<byte>();
        }
        public byte[] Read_26()
        {
            return ReadConformantArray<byte>();
        }
        public _GROUP_MEMBERSHIP[] Read_27()
        {
            return ReadConformantStructArray<_GROUP_MEMBERSHIP>();
        }
        public int[] Read_28()
        {
            return ReadFixedPrimitiveArray<int>(2);
        }
        public int[] Read_29()
        {
            return ReadFixedPrimitiveArray<int>(7);
        }
        public _KERB_SID_AND_ATTRIBUTES[] Read_30()
        {
            return ReadConformantStructArray<_KERB_SID_AND_ATTRIBUTES>();
        }
        public _GROUP_MEMBERSHIP[] Read_31()
        {
            return ReadConformantStructArray<_GROUP_MEMBERSHIP>();
        }
        public char[] Read_32()
        {
            return ReadConformantVaryingArray<char>();
        }
        public _CYPHER_BLOCK[] Read_33()
        {
            return ReadFixedStructArray<_CYPHER_BLOCK>(2);
        }
        public sbyte[] Read_34()
        {
            return ReadFixedPrimitiveArray<sbyte>(8);
        }
        public sbyte[] Read_35()
        {
            return ReadFixedPrimitiveArray<sbyte>(16);
        }
        public string Read_36()
        {
            return ReadFixedString(1);
        }
        public _RPC_UNICODE_STRING[] Read_37()
        {
            return ReadConformantStructArray<_RPC_UNICODE_STRING>();
        }
        public _SECPKG_SUPPLEMENTAL_CRED[] Read_38()
        {
            return ReadConformantStructArray<_SECPKG_SUPPLEMENTAL_CRED>();
        }
        public sbyte[] Read_39()
        {
            return ReadConformantArray<sbyte>();
        }
        public _FILETIME Read_40()
        {
            return ReadStruct<_FILETIME>();
        }
    }
    #endregion
    #region Complex Types
    public struct _PAC_DEVICE_INFO : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(UserId);
            m.WriteInt32(PrimaryGroupId);
            m.WriteEmbeddedPointer<_RPC_SID>(AccountDomainId, new System.Action<_RPC_SID>(m.Write_1));
            m.WriteInt32(AccountGroupCount);
            m.WriteEmbeddedPointer<_GROUP_MEMBERSHIP[], long>(AccountGroupIds, new System.Action<_GROUP_MEMBERSHIP[], long>(m.Write_19), AccountGroupCount);
            m.WriteInt32(SidCount);
            m.WriteEmbeddedPointer<_KERB_SID_AND_ATTRIBUTES[], long>(ExtraSids, new System.Action<_KERB_SID_AND_ATTRIBUTES[], long>(m.Write_20), SidCount);
            m.WriteInt32(DomainGroupCount);
            m.WriteEmbeddedPointer<DOMAIN_GROUP_MEMBERSHIP[], long>(DomainGroup, new System.Action<DOMAIN_GROUP_MEMBERSHIP[], long>(m.Write_21), DomainGroupCount);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            UserId = u.ReadInt32();
            PrimaryGroupId = u.ReadInt32();
            AccountDomainId = u.ReadEmbeddedPointer<_RPC_SID>(new System.Func<_RPC_SID>(u.Read_1), false);
            AccountGroupCount = u.ReadInt32();
            AccountGroupIds = u.ReadEmbeddedPointer<_GROUP_MEMBERSHIP[]>(new System.Func<_GROUP_MEMBERSHIP[]>(u.Read_19), false);
            SidCount = u.ReadInt32();
            ExtraSids = u.ReadEmbeddedPointer<_KERB_SID_AND_ATTRIBUTES[]>(new System.Func<_KERB_SID_AND_ATTRIBUTES[]>(u.Read_20), false);
            DomainGroupCount = u.ReadInt32();
            DomainGroup = u.ReadEmbeddedPointer<DOMAIN_GROUP_MEMBERSHIP[]>(new System.Func<DOMAIN_GROUP_MEMBERSHIP[]>(u.Read_21), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int UserId;
        public int PrimaryGroupId;
        public Marshal.NdrEmbeddedPointer<_RPC_SID> AccountDomainId;
        public int AccountGroupCount;
        public Marshal.NdrEmbeddedPointer<_GROUP_MEMBERSHIP[]> AccountGroupIds;
        public int SidCount;
        public Marshal.NdrEmbeddedPointer<_KERB_SID_AND_ATTRIBUTES[]> ExtraSids;
        public int DomainGroupCount;
        public Marshal.NdrEmbeddedPointer<DOMAIN_GROUP_MEMBERSHIP[]> DomainGroup;
        public static _PAC_DEVICE_INFO CreateDefault()
        {
            return new _PAC_DEVICE_INFO();
        }
        public _PAC_DEVICE_INFO(int UserId, int PrimaryGroupId, System.Nullable<_RPC_SID> AccountDomainId, int AccountGroupCount, _GROUP_MEMBERSHIP[] AccountGroupIds, int SidCount, _KERB_SID_AND_ATTRIBUTES[] ExtraSids, int DomainGroupCount, DOMAIN_GROUP_MEMBERSHIP[] DomainGroup)
        {
            this.UserId = UserId;
            this.PrimaryGroupId = PrimaryGroupId;
            this.AccountDomainId = AccountDomainId;
            this.AccountGroupCount = AccountGroupCount;
            this.AccountGroupIds = AccountGroupIds;
            this.SidCount = SidCount;
            this.ExtraSids = ExtraSids;
            this.DomainGroupCount = DomainGroupCount;
            this.DomainGroup = DomainGroup;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _RPC_SID : Marshal.INdrConformantStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteSByte(Revision);
            m.WriteSByte(SubAuthorityCount);
            m.Write_2(IdentifierAuthority);
            m.Write_22(RpcUtils.CheckNull(SubAuthority, "SubAuthority"), SubAuthorityCount);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Revision = u.ReadSByte();
            SubAuthorityCount = u.ReadSByte();
            IdentifierAuthority = u.Read_2();
            SubAuthority = u.Read_22();
        }
        int Marshal.INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public sbyte Revision;
        public sbyte SubAuthorityCount;
        public _RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        public int[] SubAuthority;
        public static _RPC_SID CreateDefault()
        {
            _RPC_SID ret = new _RPC_SID();
            ret.SubAuthority = new int[0];
            return ret;
        }
        public _RPC_SID(sbyte Revision, sbyte SubAuthorityCount, _RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority, int[] SubAuthority)
        {
            this.Revision = Revision;
            this.SubAuthorityCount = SubAuthorityCount;
            this.IdentifierAuthority = IdentifierAuthority;
            this.SubAuthority = SubAuthority;
        }

        public _RPC_SID(SecurityIdentifier sid)
        {
            byte[] binarySid = new byte[sid.BinaryLength];
            sid.GetBinaryForm(binarySid, 0);
            BinaryReader br = new BinaryReader(new MemoryStream(binarySid));

            Revision = br.ReadSByte();
            SubAuthorityCount = br.ReadSByte();
            IdentifierAuthority.Value = br.ReadBytes(6);
            SubAuthority = new int[SubAuthorityCount];
            for (int idx = 0; idx < SubAuthorityCount; ++idx)
            {
                SubAuthority[idx] = br.ReadInt32();
            }
        }

        public override string ToString()
        {
            //TODO: cache SID as string
            BinaryWriter br = new BinaryWriter(new MemoryStream());
            br.Write(Revision);
            br.Write(SubAuthorityCount);
            br.Write(IdentifierAuthority.Value);
            foreach (var sa in SubAuthority)
            {
                br.Write(sa);
            }

            return new SecurityIdentifier(((MemoryStream)br.BaseStream).ToArray(), 0).ToString();
        }
    }
    public struct _RPC_SID_IDENTIFIER_AUTHORITY : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_23(RpcUtils.CheckNull(Value, "Value"));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Value = u.Read_23();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 1;
        }
        public byte[] Value;
        public static _RPC_SID_IDENTIFIER_AUTHORITY CreateDefault()
        {
            _RPC_SID_IDENTIFIER_AUTHORITY ret = new _RPC_SID_IDENTIFIER_AUTHORITY();
            ret.Value = new byte[6];
            return ret;
        }
        public _RPC_SID_IDENTIFIER_AUTHORITY(byte[] Value)
        {
            this.Value = Value;
        }
    }

    public struct _FILETIME : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteUInt32(LowDateTime);
            m.WriteUInt32(HighDateTime);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            LowDateTime = u.ReadUInt32();
            HighDateTime = u.ReadUInt32();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public uint LowDateTime;
        public uint HighDateTime;
        public static _FILETIME CreateDefault()
        {
            var ft = new _FILETIME();
            ft.LowDateTime = 0xffffffff;
            ft.HighDateTime = 0x7fffffff;
            return ft;
        }
        public _FILETIME(uint LowDateTime, uint HighDateTime)
        {
            this.LowDateTime = LowDateTime;
            this.HighDateTime = HighDateTime;
        }
        public _FILETIME(DateTime dateTime)
        {
            var fileTime = dateTime.ToFileTimeUtc();
            LowDateTime = (uint)(fileTime & 0xffffffff);
            HighDateTime = (uint)((fileTime >> 32) & 0xffffffff);
        }

        public override string ToString()
        {
            if (LowDateTime != 0xffffffff && HighDateTime != 0x7fffffff)
            {
                return DateTime.FromFileTimeUtc((long)LowDateTime | ((long)HighDateTime << 32)).ToString("dd/MM/yyyy HH:mm:ss.fff");
            }
            else
            {
                return "";
            }
        }
    }

    public struct _GROUP_MEMBERSHIP : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(RelativeId);
            m.WriteInt32(Attributes);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            RelativeId = u.ReadInt32();
            Attributes = u.ReadInt32();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int RelativeId;
        public int Attributes;
        public static _GROUP_MEMBERSHIP CreateDefault()
        {
            return new _GROUP_MEMBERSHIP();
        }
        public _GROUP_MEMBERSHIP(int RelativeId, int Attributes)
        {
            this.RelativeId = RelativeId;
            this.Attributes = Attributes;
        }
    }
    public struct _KERB_SID_AND_ATTRIBUTES : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteEmbeddedPointer<_RPC_SID>(Sid, new System.Action<_RPC_SID>(m.Write_1));
            m.WriteInt32(Attributes);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Sid = u.ReadEmbeddedPointer<_RPC_SID>(new System.Func<_RPC_SID>(u.Read_1), false);
            Attributes = u.ReadInt32();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public Marshal.NdrEmbeddedPointer<_RPC_SID> Sid;
        public int Attributes;
        public static _KERB_SID_AND_ATTRIBUTES CreateDefault()
        {
            return new _KERB_SID_AND_ATTRIBUTES();
        }
        public _KERB_SID_AND_ATTRIBUTES(System.Nullable<_RPC_SID> Sid, int Attributes)
        {
            this.Sid = Sid;
            this.Attributes = Attributes;
        }
    }
    public struct DOMAIN_GROUP_MEMBERSHIP : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteEmbeddedPointer<_RPC_SID>(DomainId, new System.Action<_RPC_SID>(m.Write_1));
            m.WriteInt32(GroupCount);
            m.WriteEmbeddedPointer<_GROUP_MEMBERSHIP[], long>(GroupIds, new System.Action<_GROUP_MEMBERSHIP[], long>(m.Write_24), GroupCount);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            DomainId = u.ReadEmbeddedPointer<_RPC_SID>(new System.Func<_RPC_SID>(u.Read_1), false);
            GroupCount = u.ReadInt32();
            GroupIds = u.ReadEmbeddedPointer<_GROUP_MEMBERSHIP[]>(new System.Func<_GROUP_MEMBERSHIP[]>(u.Read_24), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public Marshal.NdrEmbeddedPointer<_RPC_SID> DomainId;
        public int GroupCount;
        public Marshal.NdrEmbeddedPointer<_GROUP_MEMBERSHIP[]> GroupIds;
        public static DOMAIN_GROUP_MEMBERSHIP CreateDefault()
        {
            return new DOMAIN_GROUP_MEMBERSHIP();
        }
        public DOMAIN_GROUP_MEMBERSHIP(System.Nullable<_RPC_SID> DomainId, int GroupCount, _GROUP_MEMBERSHIP[] GroupIds)
        {
            this.DomainId = DomainId;
            this.GroupCount = GroupCount;
            this.GroupIds = GroupIds;
        }
    }
    public struct _PAC_DEVICE_CLAIMS_INFO : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteEmbeddedPointer<_CLAIMS_SET_METADATA>(Claims, new System.Action<_CLAIMS_SET_METADATA>(m.Write_7));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Claims = u.ReadEmbeddedPointer<_CLAIMS_SET_METADATA>(new System.Func<_CLAIMS_SET_METADATA>(u.Read_7), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public Marshal.NdrEmbeddedPointer<_CLAIMS_SET_METADATA> Claims;
        public static _PAC_DEVICE_CLAIMS_INFO CreateDefault()
        {
            return new _PAC_DEVICE_CLAIMS_INFO();
        }
        public _PAC_DEVICE_CLAIMS_INFO(System.Nullable<_CLAIMS_SET_METADATA> Claims)
        {
            this.Claims = Claims;
        }
    }
    public struct _CLAIMS_SET_METADATA : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(ulClaimsSetSize);
            m.WriteEmbeddedPointer<byte[], long>(ClaimsSet, new System.Action<byte[], long>(m.Write_25), ulClaimsSetSize);
            m.WriteEnum16(usCompressionFormat);
            m.WriteInt32(ulUncompressedClaimsSetSize);
            m.WriteInt16(usReservedType);
            m.WriteInt32(ulReservedFieldSize);
            m.WriteEmbeddedPointer<byte[], long>(ReservedField, new System.Action<byte[], long>(m.Write_26), ulReservedFieldSize);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            ulClaimsSetSize = u.ReadInt32();
            ClaimsSet = u.ReadEmbeddedPointer<byte[]>(new System.Func<byte[]>(u.Read_25), false);
            usCompressionFormat = u.ReadEnum16();
            ulUncompressedClaimsSetSize = u.ReadInt32();
            usReservedType = u.ReadInt16();
            ulReservedFieldSize = u.ReadInt32();
            ReservedField = u.ReadEmbeddedPointer<byte[]>(new System.Func<byte[]>(u.Read_26), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int ulClaimsSetSize;
        public Marshal.NdrEmbeddedPointer<byte[]> ClaimsSet;
        public Marshal.NdrEnum16 usCompressionFormat;
        public int ulUncompressedClaimsSetSize;
        public short usReservedType;
        public int ulReservedFieldSize;
        public Marshal.NdrEmbeddedPointer<byte[]> ReservedField;
        public static _CLAIMS_SET_METADATA CreateDefault()
        {
            return new _CLAIMS_SET_METADATA();
        }
        public _CLAIMS_SET_METADATA(int ulClaimsSetSize, byte[] ClaimsSet, Marshal.NdrEnum16 usCompressionFormat, int ulUncompressedClaimsSetSize, short usReservedType, int ulReservedFieldSize, byte[] ReservedField)
        {
            this.ulClaimsSetSize = ulClaimsSetSize;
            this.ClaimsSet = ClaimsSet;
            this.usCompressionFormat = usCompressionFormat;
            this.ulUncompressedClaimsSetSize = ulUncompressedClaimsSetSize;
            this.usReservedType = usReservedType;
            this.ulReservedFieldSize = ulReservedFieldSize;
            this.ReservedField = ReservedField;
        }
    }
    public struct _UPN_DNS_INFO : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt16(UpnLength);
            m.WriteInt16(UpnOffset);
            m.WriteInt16(DnsDomainNameLength);
            m.WriteInt16(DnsDomainNameOffset);
            m.WriteInt32(Flags);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            UpnLength = u.ReadInt16();
            UpnOffset = u.ReadInt16();
            DnsDomainNameLength = u.ReadInt16();
            DnsDomainNameOffset = u.ReadInt16();
            Flags = u.ReadInt32();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public short UpnLength;
        public short UpnOffset;
        public short DnsDomainNameLength;
        public short DnsDomainNameOffset;
        public int Flags;
        public static _UPN_DNS_INFO CreateDefault()
        {
            return new _UPN_DNS_INFO();
        }
        public _UPN_DNS_INFO(short UpnLength, short UpnOffset, short DnsDomainNameLength, short DnsDomainNameOffset, int Flags)
        {
            this.UpnLength = UpnLength;
            this.UpnOffset = UpnOffset;
            this.DnsDomainNameLength = DnsDomainNameLength;
            this.DnsDomainNameOffset = DnsDomainNameOffset;
            this.Flags = Flags;
        }
    }
    public struct _KERB_VALIDATION_INFO : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_40(LogonTime);
            m.Write_40(LogoffTime);
            m.Write_40(KickOffTime);
            m.Write_40(PasswordLastSet);
            m.Write_40(PasswordCanChange);
            m.Write_40(PasswordMustChange);
            m.Write_10(EffectiveName);
            m.Write_10(FullName);
            m.Write_10(LogonScript);
            m.Write_10(ProfilePath);
            m.Write_10(HomeDirectory);
            m.Write_10(HomeDirectoryDrive);
            m.WriteInt16(LogonCount);
            m.WriteInt16(BadPasswordCount);
            m.WriteInt32(UserId);
            m.WriteInt32(PrimaryGroupId);
            m.WriteInt32(GroupCount);
            m.WriteEmbeddedPointer<_GROUP_MEMBERSHIP[], long>(GroupIds, new System.Action<_GROUP_MEMBERSHIP[], long>(m.Write_27), GroupCount);
            m.WriteInt32(UserFlags);
            m.Write_11(UserSessionKey);
            m.Write_10(LogonServer);
            m.Write_10(LogonDomainName);
            m.WriteEmbeddedPointer<_RPC_SID>(LogonDomainId, new System.Action<_RPC_SID>(m.Write_1));
            m.Write_28(RpcUtils.CheckNull(Reserved1, "Reserved1"));
            m.WriteInt32(UserAccountControl);
            m.Write_29(RpcUtils.CheckNull(Reserved3, "Reserved3"));
            m.WriteInt32(SidCount);
            m.WriteEmbeddedPointer<_KERB_SID_AND_ATTRIBUTES[], long>(ExtraSids, new System.Action<_KERB_SID_AND_ATTRIBUTES[], long>(m.Write_30), SidCount);
            m.WriteEmbeddedPointer<_RPC_SID>(ResourceGroupDomainSid, new System.Action<_RPC_SID>(m.Write_1));
            m.WriteInt32(ResourceGroupCount);
            m.WriteEmbeddedPointer<_GROUP_MEMBERSHIP[], long>(ResourceGroupIds, new System.Action<_GROUP_MEMBERSHIP[], long>(m.Write_31), ResourceGroupCount);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            LogonTime = u.Read_40();
            LogoffTime = u.Read_40();
            KickOffTime = u.Read_40();
            PasswordLastSet = u.Read_40();
            PasswordCanChange = u.Read_40();
            PasswordMustChange = u.Read_40();
            EffectiveName = u.Read_10();
            FullName = u.Read_10();
            LogonScript = u.Read_10();
            ProfilePath = u.Read_10();
            HomeDirectory = u.Read_10();
            HomeDirectoryDrive = u.Read_10();
            LogonCount = u.ReadInt16();
            BadPasswordCount = u.ReadInt16();
            UserId = u.ReadInt32();
            PrimaryGroupId = u.ReadInt32();
            GroupCount = u.ReadInt32();
            GroupIds = u.ReadEmbeddedPointer<_GROUP_MEMBERSHIP[]>(new System.Func<_GROUP_MEMBERSHIP[]>(u.Read_27), false);
            UserFlags = u.ReadInt32();
            UserSessionKey = u.Read_11();
            LogonServer = u.Read_10();
            LogonDomainName = u.Read_10();
            LogonDomainId = u.ReadEmbeddedPointer<_RPC_SID>(new System.Func<_RPC_SID>(u.Read_1), false);
            Reserved1 = u.Read_28();
            UserAccountControl = u.ReadInt32();
            Reserved3 = u.Read_29();
            SidCount = u.ReadInt32();
            ExtraSids = u.ReadEmbeddedPointer<_KERB_SID_AND_ATTRIBUTES[]>(new System.Func<_KERB_SID_AND_ATTRIBUTES[]>(u.Read_30), false);
            ResourceGroupDomainSid = u.ReadEmbeddedPointer<_RPC_SID>(new System.Func<_RPC_SID>(u.Read_1), false);
            ResourceGroupCount = u.ReadInt32();
            ResourceGroupIds = u.ReadEmbeddedPointer<_GROUP_MEMBERSHIP[]>(new System.Func<_GROUP_MEMBERSHIP[]>(u.Read_31), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public _FILETIME LogonTime;
        public _FILETIME LogoffTime;
        public _FILETIME KickOffTime;
        public _FILETIME PasswordLastSet;
        public _FILETIME PasswordCanChange;
        public _FILETIME PasswordMustChange;
        public _RPC_UNICODE_STRING EffectiveName;
        public _RPC_UNICODE_STRING FullName;
        public _RPC_UNICODE_STRING LogonScript;
        public _RPC_UNICODE_STRING ProfilePath;
        public _RPC_UNICODE_STRING HomeDirectory;
        public _RPC_UNICODE_STRING HomeDirectoryDrive;
        public short LogonCount;
        public short BadPasswordCount;
        public int UserId;
        public int PrimaryGroupId;
        public int GroupCount;
        public Marshal.NdrEmbeddedPointer<_GROUP_MEMBERSHIP[]> GroupIds;
        public int UserFlags;
        public _USER_SESSION_KEY UserSessionKey;
        public _RPC_UNICODE_STRING LogonServer;
        public _RPC_UNICODE_STRING LogonDomainName;
        public Marshal.NdrEmbeddedPointer<_RPC_SID> LogonDomainId;
        public int[] Reserved1;
        public int UserAccountControl;
        public int[] Reserved3;
        public int SidCount;
        public Marshal.NdrEmbeddedPointer<_KERB_SID_AND_ATTRIBUTES[]> ExtraSids;
        public Marshal.NdrEmbeddedPointer<_RPC_SID> ResourceGroupDomainSid;
        public int ResourceGroupCount;
        public Marshal.NdrEmbeddedPointer<_GROUP_MEMBERSHIP[]> ResourceGroupIds;
        public static _KERB_VALIDATION_INFO CreateDefault()
        {
            _KERB_VALIDATION_INFO ret = new _KERB_VALIDATION_INFO();
            ret.Reserved1 = new int[2];
            ret.Reserved3 = new int[7];
            return ret;
        }
        public _KERB_VALIDATION_INFO(
                    _FILETIME LogonTime,
                    _FILETIME LogoffTime,
                    _FILETIME KickOffTime,
                    _FILETIME PasswordLastSet,
                    _FILETIME PasswordCanChange,
                    _FILETIME PasswordMustChange,
                    _RPC_UNICODE_STRING EffectiveName,
                    _RPC_UNICODE_STRING FullName,
                    _RPC_UNICODE_STRING LogonScript,
                    _RPC_UNICODE_STRING ProfilePath,
                    _RPC_UNICODE_STRING HomeDirectory,
                    _RPC_UNICODE_STRING HomeDirectoryDrive,
                    short LogonCount,
                    short BadPasswordCount,
                    int UserId,
                    int PrimaryGroupId,
                    int GroupCount,
                    _GROUP_MEMBERSHIP[] GroupIds,
                    int UserFlags,
                    _USER_SESSION_KEY UserSessionKey,
                    _RPC_UNICODE_STRING LogonServer,
                    _RPC_UNICODE_STRING LogonDomainName,
                    System.Nullable<_RPC_SID> LogonDomainId,
                    int[] Reserved1,
                    int UserAccountControl,
                    int[] Reserved3,
                    int SidCount,
                    _KERB_SID_AND_ATTRIBUTES[] ExtraSids,
                    System.Nullable<_RPC_SID> ResourceGroupDomainSid,
                    int ResourceGroupCount,
                    _GROUP_MEMBERSHIP[] ResourceGroupIds)
        {
            this.LogonTime = LogonTime;
            this.LogoffTime = LogoffTime;
            this.KickOffTime = KickOffTime;
            this.PasswordLastSet = PasswordLastSet;
            this.PasswordCanChange = PasswordCanChange;
            this.PasswordMustChange = PasswordMustChange;
            this.EffectiveName = EffectiveName;
            this.FullName = FullName;
            this.LogonScript = LogonScript;
            this.ProfilePath = ProfilePath;
            this.HomeDirectory = HomeDirectory;
            this.HomeDirectoryDrive = HomeDirectoryDrive;
            this.LogonCount = LogonCount;
            this.BadPasswordCount = BadPasswordCount;
            this.UserId = UserId;
            this.PrimaryGroupId = PrimaryGroupId;
            this.GroupCount = GroupCount;
            this.GroupIds = GroupIds;
            this.UserFlags = UserFlags;
            this.UserSessionKey = UserSessionKey;
            this.LogonServer = LogonServer;
            this.LogonDomainName = LogonDomainName;
            this.LogonDomainId = LogonDomainId;
            this.Reserved1 = Reserved1;
            this.UserAccountControl = UserAccountControl;
            this.Reserved3 = Reserved3;
            this.SidCount = SidCount;
            this.ExtraSids = ExtraSids;
            this.ResourceGroupDomainSid = ResourceGroupDomainSid;
            this.ResourceGroupCount = ResourceGroupCount;
            this.ResourceGroupIds = ResourceGroupIds;
        }
    }

    public struct _RPC_UNICODE_STRING : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt16(Length);
            m.WriteInt16(MaximumLength);
            m.WriteEmbeddedPointer<char[], long, long>(Buffer, new System.Action<char[], long, long>(m.Write_32), (MaximumLength / 2), (Length / 2));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Length = u.ReadInt16();
            MaximumLength = u.ReadInt16();
            Buffer = u.ReadEmbeddedPointer<char[]>(new System.Func<char[]>(u.Read_32), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public short Length;
        public short MaximumLength;
        public Marshal.NdrEmbeddedPointer<char[]> Buffer;
        public static _RPC_UNICODE_STRING CreateDefault()
        {
            return new _RPC_UNICODE_STRING();
        }
        public _RPC_UNICODE_STRING(short Length, short MaximumLength, char[] Buffer)
        {
            this.Length = Length;
            this.MaximumLength = MaximumLength;
            this.Buffer = Buffer;
        }

        public _RPC_UNICODE_STRING(string value)
        {
            this.Length = (short)(value.Length * 2);
            if (value.Length > 0)
            {
                this.MaximumLength = (short)(this.Length + 2);
                value = value + '\0';
            }
            else
            {
                this.MaximumLength = this.Length;
            }
            this.Buffer = value.ToCharArray();
        }

        public override string ToString()
        {
            if (Buffer != null && Buffer.GetValue() != null)
            {
                return new string(Buffer.GetValue(), 0, Length / 2);
            }
            else
            {
                return null;
            }
        }
    }
    public struct _USER_SESSION_KEY : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_33(RpcUtils.CheckNull(data, "data"));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            data = u.Read_33();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 1;
        }
        public _CYPHER_BLOCK[] data;
        public static _USER_SESSION_KEY CreateDefault()
        {
            _USER_SESSION_KEY ret = new _USER_SESSION_KEY();
            ret.data = new _CYPHER_BLOCK[2];
            ret.data[0].data = new sbyte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            ret.data[1].data = new sbyte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            return ret;
        }
        public _USER_SESSION_KEY(_CYPHER_BLOCK[] data)
        {
            this.data = data;
        }
    }
    public struct _CYPHER_BLOCK : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_34(RpcUtils.CheckNull(data, "data"));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            data = u.Read_34();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 1;
        }
        public sbyte[] data;
        public static _CYPHER_BLOCK CreateDefault()
        {
            _CYPHER_BLOCK ret = new _CYPHER_BLOCK();
            ret.data = new sbyte[8];
            return ret;
        }
        public _CYPHER_BLOCK(sbyte[] data)
        {
            this.data = data;
        }
    }
    public struct _PAC_INFO_BUFFER : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(ulType);
            m.WriteInt32(cbBufferSize);
            m.WriteInt64(Offset);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            ulType = u.ReadInt32();
            cbBufferSize = u.ReadInt32();
            Offset = u.ReadInt64();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 8;
        }
        public int ulType;
        public int cbBufferSize;
        public long Offset;
        public static _PAC_INFO_BUFFER CreateDefault()
        {
            return new _PAC_INFO_BUFFER();
        }
        public _PAC_INFO_BUFFER(int ulType, int cbBufferSize, long Offset)
        {
            this.ulType = ulType;
            this.cbBufferSize = cbBufferSize;
            this.Offset = Offset;
        }
    }
    public struct _NTLM_SUPPLEMENTAL_CREDENTIAL : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Version);
            m.WriteInt32(Flags);
            m.Write_35(RpcUtils.CheckNull(LmPassword, "LmPassword"));
            m.Write_35(RpcUtils.CheckNull(NtPassword, "NtPassword"));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Version = u.ReadInt32();
            Flags = u.ReadInt32();
            LmPassword = u.Read_35();
            NtPassword = u.Read_35();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Version;
        public int Flags;
        public sbyte[] LmPassword;
        public sbyte[] NtPassword;
        public static _NTLM_SUPPLEMENTAL_CREDENTIAL CreateDefault()
        {
            _NTLM_SUPPLEMENTAL_CREDENTIAL ret = new _NTLM_SUPPLEMENTAL_CREDENTIAL();
            ret.LmPassword = new sbyte[16];
            ret.NtPassword = new sbyte[16];
            return ret;
        }
        public _NTLM_SUPPLEMENTAL_CREDENTIAL(int Version, int Flags, sbyte[] LmPassword, sbyte[] NtPassword)
        {
            this.Version = Version;
            this.Flags = Flags;
            this.LmPassword = LmPassword;
            this.NtPassword = NtPassword;
        }
    }
    public struct _PAC_CLIENT_INFO : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_3(ClientId);
            m.WriteInt16(NameLength);
            m.Write_36(RpcUtils.CheckNull(Name, "Name"));
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            ClientId = u.Read_3();
            NameLength = u.ReadInt16();
            Name = u.Read_36();
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public _GROUP_MEMBERSHIP ClientId;
        public short NameLength;
        public string Name;
        public static _PAC_CLIENT_INFO CreateDefault()
        {
            _PAC_CLIENT_INFO ret = new _PAC_CLIENT_INFO();
            ret.Name = new string('\0', 1);
            return ret;
        }
        public _PAC_CLIENT_INFO(_GROUP_MEMBERSHIP ClientId, short NameLength, string Name)
        {
            this.ClientId = ClientId;
            this.NameLength = NameLength;
            this.Name = Name;
        }
    }
    public struct _S4U_DELEGATION_INFO : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_10(S4U2proxyTarget);
            m.WriteInt32(TransitedListSize);
            m.WriteEmbeddedPointer<_RPC_UNICODE_STRING[], long>(S4UTransitedServices, new System.Action<_RPC_UNICODE_STRING[], long>(m.Write_37), TransitedListSize);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            S4U2proxyTarget = u.Read_10();
            TransitedListSize = u.ReadInt32();
            S4UTransitedServices = u.ReadEmbeddedPointer<_RPC_UNICODE_STRING[]>(new System.Func<_RPC_UNICODE_STRING[]>(u.Read_37), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public _RPC_UNICODE_STRING S4U2proxyTarget;
        public int TransitedListSize;
        public Marshal.NdrEmbeddedPointer<_RPC_UNICODE_STRING[]> S4UTransitedServices;
        public static _S4U_DELEGATION_INFO CreateDefault()
        {
            return new _S4U_DELEGATION_INFO();
        }
        public _S4U_DELEGATION_INFO(_RPC_UNICODE_STRING S4U2proxyTarget, int TransitedListSize, _RPC_UNICODE_STRING[] S4UTransitedServices)
        {
            this.S4U2proxyTarget = S4U2proxyTarget;
            this.TransitedListSize = TransitedListSize;
            this.S4UTransitedServices = S4UTransitedServices;
        }
    }
    public struct _PAC_CREDENTIAL_DATA : Marshal.INdrConformantStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(CredentialCount);
            m.Write_38(RpcUtils.CheckNull(Credentials, "Credentials"), CredentialCount);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            CredentialCount = u.ReadInt32();
            Credentials = u.Read_38();
        }
        int Marshal.INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int CredentialCount;
        public _SECPKG_SUPPLEMENTAL_CRED[] Credentials;
        public static _PAC_CREDENTIAL_DATA CreateDefault()
        {
            _PAC_CREDENTIAL_DATA ret = new _PAC_CREDENTIAL_DATA();
            ret.Credentials = new _SECPKG_SUPPLEMENTAL_CRED[0];
            return ret;
        }
        public _PAC_CREDENTIAL_DATA(int CredentialCount, _SECPKG_SUPPLEMENTAL_CRED[] Credentials)
        {
            this.CredentialCount = CredentialCount;
            this.Credentials = Credentials;
        }
    }
    public struct _SECPKG_SUPPLEMENTAL_CRED : Marshal.INdrStructure
    {
        void Marshal.INdrStructure.Marshal(Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_10(PackageName);
            m.WriteInt32(CredentialSize);
            m.WriteEmbeddedPointer<sbyte[], long>(Credentials, new System.Action<sbyte[], long>(m.Write_39), CredentialSize);
        }
        void Marshal.INdrStructure.Unmarshal(Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            PackageName = u.Read_10();
            CredentialSize = u.ReadInt32();
            Credentials = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_39), false);
        }
        int Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public _RPC_UNICODE_STRING PackageName;
        public int CredentialSize;
        public Marshal.NdrEmbeddedPointer<sbyte[]> Credentials;
        public static _SECPKG_SUPPLEMENTAL_CRED CreateDefault()
        {
            return new _SECPKG_SUPPLEMENTAL_CRED();
        }
        public _SECPKG_SUPPLEMENTAL_CRED(_RPC_UNICODE_STRING PackageName, int CredentialSize, sbyte[] Credentials)
        {
            this.PackageName = PackageName;
            this.CredentialSize = CredentialSize;
            this.Credentials = Credentials;
        }
    }
    #endregion
}

