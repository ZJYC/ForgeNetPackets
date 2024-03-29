﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZNET_GUI
{
    class Basic
    {

        public void MessageBox(string Inf)
        {
            System.Windows.Forms.MessageBox.Show(Inf);
        }
        public string MacStringSplit(string MacStringNoSplit)
        {
            string str1 = "";
            for (int i = 0; i < MacStringNoSplit.Length; i++)
            {
                str1 += MacStringNoSplit[i].ToString();
                if ((i % 2 == 1) && (i < MacStringNoSplit.Length - 1)) str1 += "-";
            }
            return str1;
        }
        public string byteToHexStr(byte[] bytes)
        {
            string returnStr = "";
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr += bytes[i].ToString("X2") + " ";

                }
            }
            return returnStr;
        }
        public byte[] HexStrToBytes(string hexStr)
        {
            hexStr = hexStr.Replace(" ","");

            if (string.IsNullOrEmpty(hexStr))
            {
                return new byte[0];
            }

            if (hexStr.StartsWith("0x"))
            {
                hexStr = hexStr.Remove(0, 2);
            }

            var count = hexStr.Length;

            if (count % 2 == 1)
            {
                throw new ArgumentException("Invalid length of bytes:" + count);
            }

            var byteCount = count / 2;
            var result = new byte[byteCount];
            for (int ii = 0; ii < byteCount; ++ii)
            {
                var tempBytes = Byte.Parse(hexStr.Substring(2 * ii, 2), System.Globalization.NumberStyles.HexNumber);
                result[ii] = tempBytes;
            }

            return result;
        }
        public byte[] HexStrToBytes(string hexStr,int Len)
        {
            List<byte> Temp = new List<byte>(HexStrToBytes(hexStr));

            for(int i = 0;i < Len - Temp.Count;i++)
            {
                Temp.Add(0x00);
            }

            return Temp.ToArray();

        }
        public string RemoveSpace(string Input)
        {
            return Input.Replace(" ","");
        }
        public UInt16 CheckSumEx(byte[] buff1, byte[] buff2)
        {
            UInt32 Chksum = 0;
            UInt16 Res = 0;

            List<byte> Buff1_ = new List<byte>(buff1);
            if (Buff1_.Count % 2 == 1) Buff1_.Add(0);
            List<byte> Buff2_ = new List<byte>(buff2);
            if (Buff2_.Count % 2 == 1) Buff2_.Add(0);

            for(int i = 0;i < Buff1_.Count;i += 2)
            {
                Chksum += (UInt32)(Buff1_[i] * 256 + Buff1_[i + 1]);
            }
            for (int i = 0; i < Buff2_.Count; i += 2)
            {
                Chksum += (UInt32)(Buff2_[i] * 256 + Buff2_[i + 1]);
            }
            while ((Chksum & 0xFFFF0000) != 0)
            {
                Chksum = (Chksum >> 16) + (Chksum & 0xFFFF);
            }
            Res = (UInt16)Chksum;
            Res = (UInt16)(~Res);
            return Res;
        }
        public UInt16 CheckSum(byte[] buff)
        {
            UInt32 Sum = 0;UInt16 ChkSum = 0;
            List<byte> ListTemp = new List<byte>(buff);
            if (ListTemp.Count % 2 == 1) ListTemp.Add(0x00);
            for(int i = 0;i < ListTemp.Count;i += 2)
            {
                Sum += (UInt32)(ListTemp[i] * 256 + ListTemp[i + 1]);
            }
            while((Sum & 0xFFFF0000) != 0)
            {
                Sum = (Sum >> 16) + (Sum & 0xFFFF);
            }
            ChkSum = (UInt16)Sum;
            ChkSum = (UInt16)(~ChkSum);
            return ChkSum;
        }
    }
}
