using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.IO;
using PacketDotNet;
using System.Net.NetworkInformation;

namespace ZNET_GUI
{

    class IP_Packet
    {
        public byte Version { get; set; }
        public byte HeaderLen { get; set; }
        public byte ServiceID { get; set; }
        public UInt16 TotolLen { get; set; }
        public UInt16 SN { get; set; }
        public bool? DF { get; set; }
        public bool? MF { get; set; }
        public UInt16 Shift { get; set; }
        public byte TTL { get; set; }
        public byte Protocol { get; set; }
        public UInt16 Chksum { get; set; }
        public string SourceIP { get; set; }
        public string DstIP { get; set;}
        public string OptionPad { get; set; }
        public string Data { get; set; }

        public Dictionary<string, UInt16> ProtocolDic = new Dictionary<string, ushort>() { {"TCP",6 },{ "UDP",17},{ "ICMP",1} };

        public byte[] GenPacket()
        {
            Basic basic = new Basic();
            List<byte> Frm = new List<byte>();
            //如果长度为0则会自行计算
            if (this.HeaderLen == 0)
            {
                this.HeaderLen = (byte)(this.OptionPad.Length / 2 + 20);
            }
            if (this.TotolLen == 0)
            {
                this.TotolLen = (UInt16)(this.HeaderLen + this.Data.Length / 2);
            }
            //如果CRC不为空，就不计算
            Frm.Add((byte)((this.Version << 4) | (this.HeaderLen /4)));
            Frm.Add(this.ServiceID);
            Frm.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)this.TotolLen)));
            Frm.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)this.SN)));
            UInt16 Temp = (UInt16)((((this.DF == true ? 1 : 0) * 128) + ((this.MF == true ? 1 : 0) * 128))*256 + this.Shift);
            Frm.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)Temp)));
            Frm.Add(this.TTL);
            Frm.Add(this.Protocol);
            Frm.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)this.Chksum)));
            if (this.Chksum == 0)
            {
                UInt16 Crc = basic.CheckSum(Frm.ToArray());
                Frm.RemoveAt(Frm.Count - 1);
                Frm.RemoveAt(Frm.Count - 1);
                this.Chksum = Crc;
                Frm.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)Crc)));
            }
            Frm.AddRange(BitConverter.GetBytes((UInt32)IPAddress.HostToNetworkOrder((Int32)IPAddress.Parse(SourceIP).Address)));
            Frm.AddRange(BitConverter.GetBytes((UInt32)IPAddress.HostToNetworkOrder((Int32)IPAddress.Parse(DstIP).Address)));
            Frm.AddRange(basic.HexStrToBytes(this.OptionPad));
            Frm.AddRange(basic.HexStrToBytes(this.Data));
            return Frm.ToArray();
        }

    }

    class GeneratePackets
    {
        public ArpPacket GetArpPacketFromGUI(ArpOperation arpOperation,string RemoteMAC,string RemoteIP,string LocalMAC,string LocalIP)
        {
            ArpPacket arpPacket = new ArpPacket(
                arpOperation,
                PhysicalAddress.Parse(RemoteMAC),
                IPAddress.Parse(RemoteIP),
                PhysicalAddress.Parse(LocalMAC),
                IPAddress.Parse(LocalIP));
            return arpPacket;
        }
        public EthernetPacket GetEthPacketFromGUI(string Protocol,string LocalMAC,string RemoteMAC)
        {
            EthernetType ethernetType;
            if(Protocol == "ARP")
            {
                ethernetType = EthernetType.Arp;
            }
            else
            {
                ethernetType = EthernetType.None;
            }
            EthernetPacket ethernet = new EthernetPacket(PhysicalAddress.Parse(LocalMAC),
                PhysicalAddress.Parse(RemoteMAC), ethernetType);
            return ethernet;
        }
    }
}
