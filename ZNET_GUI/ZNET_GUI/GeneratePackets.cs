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

    class Z_TCP_Packet
    {
        public string SrcPort;
        public string DstPort;
        public string SnNum;
        public string AcNum;
        public string HeaderLen;
        public string Resv;
        public bool? CWR;
        public bool? ECE;
        public bool? URG;
        public bool? ACK;
        public bool? PSH;
        public bool? RST;
        public bool? SYN;
        public bool? FIN;
        public string WinSize;
        public string ChkSum;
        public string UrgPointer;
        public string Option;
        public string Data;

        //public byte[] GenPacket()
        //{
        //    List<byte> Temp = new List<byte>();
        //    Temp.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder(Int16.Parse(this.SrcPort))));
        //    Temp.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder(Int16.Parse(this.DstPort))));
        //    Temp.AddRange(BitConverter.GetBytes((UInt32)IPAddress.HostToNetworkOrder(Int32.Parse(this.SnNum))));
        //    Temp.AddRange(BitConverter.GetBytes((UInt32)IPAddress.HostToNetworkOrder(Int32.Parse(this.AcNum))));
        //    return 
        //}
    }

    class Z_ARP_Packet
    {
        public UInt16 H_Type = 0x0001;
        public UInt16 P_Type = 0x0800;
        public byte H_Len = 0x06;
        public byte P_Len = 0x04;
        public string Opt;
        public byte[] LocalMAC = new byte[6];
        public byte[] LocalIP = new byte[4];
        public byte[] DstMAC = new byte[6];
        public byte[] DstIP = new byte[4];
        public Dictionary<string, UInt16> ARP_OptDic = new Dictionary<string, ushort>() { { "Request", 0x0001 }, { "Reply", 0x0002 }, };

        public byte[] GenPacket()
        {
            List<byte> Temp = new List<byte>();
            Temp.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)this.H_Type)));
            Temp.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)this.P_Type)));
            Temp.Add(H_Len);
            Temp.Add(P_Len);
            UInt16 Opt;
            ARP_OptDic.TryGetValue(this.Opt, out Opt);
            Temp.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)Opt)));
            Temp.AddRange(LocalMAC);
            Temp.AddRange(LocalIP);
            Temp.AddRange(DstMAC);
            Temp.AddRange(DstIP);
            return Temp.ToArray();
        }
    }

    class Z_ETH_Packet
    {
        public byte[] DstMAC = new byte[6];
        public byte[] SourceMAC = new byte[6];
        public string Type;
        public byte[] Data = new byte[0];
        public Dictionary<string, UInt16> ProtocolDic = new Dictionary<string, ushort>() { {"ARP",0x0806 },{"IP",0x0800 }, };
        public byte[] GenPacket()
        {
            List<byte> Temp = new List<byte>();
            Temp.AddRange(this.DstMAC);
            Temp.AddRange(this.SourceMAC);
            UInt16 Type;
            ProtocolDic.TryGetValue(this.Type, out Type);
            Temp.AddRange(BitConverter.GetBytes((UInt16)IPAddress.HostToNetworkOrder((Int16)Type)));
            Temp.AddRange(this.Data);
            return Temp.ToArray();
        }
    }

    class ZJ_IP_Packet
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
            Frm.AddRange(IPAddress.Parse(SourceIP).GetAddressBytes());
            Frm.AddRange(IPAddress.Parse(DstIP).GetAddressBytes());
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
