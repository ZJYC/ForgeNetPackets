using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace ZNET_GUI
{
    class SimplePcapFile
    {
        public void FileWrite(string Path,byte [] DataAppend)
        {
            using (FileStream fs = new FileStream(Path, FileMode.Append))
            {
                List<byte> Temp = new List<byte>();
                Temp.AddRange(BitConverter.GetBytes((UInt32)0x00));
                Temp.AddRange(BitConverter.GetBytes((UInt32)0x00));
                Temp.AddRange(BitConverter.GetBytes((UInt32)DataAppend.Length));
                Temp.AddRange(BitConverter.GetBytes((UInt32)DataAppend.Length));
                Temp.AddRange(DataAppend);
                fs.Write(Temp.ToArray(), 0, Temp.Count);
                fs.Flush();
            }
        }
        public byte[] FileRead(string Path)
        {
            byte[] vs;
            using (FileStream fs = new FileStream(Path, FileMode.Open))
            {
                byte[] Res = new byte[fs.Length];
                fs.Read(Res,0,(int)fs.Length);
                vs = (byte [])Res.Clone();
            }
            return vs;
        }
    }
}
