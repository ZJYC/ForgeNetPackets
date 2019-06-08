using System;
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
    }
}
