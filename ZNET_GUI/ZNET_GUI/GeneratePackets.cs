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
    class Z_UDP_Packet
    {
        public string SrcPort = "0";
        public string DstPort = "0";
        public string Data = "00";

        Basic basic = new Basic();

        public byte [] GenPacket()
        {
            List<byte> Temp = new List<byte>();

            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(SrcPort))));
            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(DstPort))));
            short Len = (short)(8 + basic.RemoveSpace(Data).Length / 2);
            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(Len)));
            Temp.Add(0);
            Temp.Add(0);
            Temp.AddRange(basic.HexStrToBytes(Data));
            return Temp.ToArray();

        }
    }

    class Z_TCP_Packet
    {
        public string SrcPort = "0";
        public string DstPort = "0";
        public string SnNum = "0";
        public string AcNum = "0";
        public string HeaderLen = "0";
        public string Resv = "0";
        public bool? CWR = false;
        public bool? ECE = false;
        public bool? URG = false;
        public bool? ACK = false;
        public bool? PSH = false;
        public bool? RST = false;
        public bool? SYN = false;
        public bool? FIN = false;
        public string WinSize = "0";
        public string ChkSum = "0";
        public string UrgPointer = "0";
        /* 长度必须是4的倍数 */
        public string Option = "00";
        public string Data = "00";

        Basic basic = new Basic();

        public byte[] GenPacket()
        {
            List<byte> Temp = new List<byte>();
            try
            {
                byte Bits = 0;
                Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(this.SrcPort))));
                Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(this.DstPort))));
                Temp.AddRange(BitConverter.GetBytes((UInt32)IPAddress.HostToNetworkOrder(Int32.Parse(this.SnNum))));
                Temp.AddRange(BitConverter.GetBytes((UInt32)IPAddress.HostToNetworkOrder(Int32.Parse(this.AcNum))));
                this.HeaderLen = (((20 + basic.RemoveSpace(this.Option).Length / 2) / 4) << 4).ToString();
                Temp.Add((byte)(byte.Parse(this.HeaderLen) + byte.Parse(this.Resv)));
                if (CWR == true) Bits |= (1 << 7);
                if (ECE == true) Bits |= (1 << 6);
                if (URG == true) Bits |= (1 << 5);
                if (ACK == true) Bits |= (1 << 4);
                if (PSH == true) Bits |= (1 << 3);
                if (RST == true) Bits |= (1 << 2);
                if (SYN == true) Bits |= (1 << 1);
                if (FIN == true) Bits |= (1 << 0);
                Temp.Add(Bits);
                Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(this.WinSize))));
                /*CRC */
                Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse("0"))));
                Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(this.UrgPointer))));
                Temp.AddRange(basic.HexStrToBytes(this.Option));
                Temp.AddRange(basic.HexStrToBytes(this.Data));
            }
            catch
            {
                System.Windows.MessageBox.Show("当生成TCP数据包的时候发生未知错误");
            }
            return Temp.ToArray();
        }
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

    class JX_IP_Packet
    {
        public string ID = "0";
        public bool? MF = false;
        public bool? DF = false;
        public string Shift = "0";
        public string TTL = "64";
        public string Protocol = "TCP";
        public string CheckSum = "0";
        public string SrcIP = "0.0.0.0";
        public string DstIP = "0.0.0.0";
        public string Option = "";
        public string Data = "";

        public Dictionary<string, byte> ProtocolDic = new Dictionary<string, byte>() {
            { "TCP", 6 },
            { "UDP", 17 },
            { "ICMP", 1 } };

        Basic basic = new Basic();

        public byte [] GenPacket()
        {
            List<byte> Temp = new List<byte>();
            byte VersionHeaderLen = (byte)((4 << 4) | ((20 + basic.RemoveSpace(Option).Length / 2) / 4));
            Temp.Add(VersionHeaderLen);
            Temp.Add(0);
            short TotalLen = (short)((20 + basic.RemoveSpace(Option).Length / 2) + basic.RemoveSpace(Data).Length / 2);
            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder((short)TotalLen)));
            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(short.Parse(ID))));
            short ShiftFlg = 0;
            if (MF == true) ShiftFlg |= (1 << 13);
            if (DF == true) ShiftFlg |= (1 << 14);
            ShiftFlg |= short.Parse(Shift);
            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder((short)ShiftFlg)));
            Temp.Add(byte.Parse(TTL));
            Temp.Add((byte)ProtocolDic[Protocol]);
            Temp.Add(0);
            Temp.Add(0);
            Temp.AddRange(IPAddress.Parse(SrcIP).GetAddressBytes());
            Temp.AddRange(IPAddress.Parse(DstIP).GetAddressBytes());
            if (Option != "") Temp.AddRange(basic.HexStrToBytes(Option));
            UInt16 CHK = basic.CheckSum(Temp.ToArray());
            List<byte> Res = new List<byte>();
            Res.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder((short)CHK)));
            Temp[10] = Res[0];
            Temp[11] = Res[1];
            if (Data != "") Temp.AddRange(basic.HexStrToBytes(Data));
            if(Protocol == "TCP")
            {
                byte[] Pseudo = GenPseudo();
                short Chksum = (short)basic.CheckSumEx(Pseudo, basic.HexStrToBytes(Data));
                List<byte> T = new List<byte>();
                T.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(Chksum)));
                Temp[(20 + Option.Length / 2) + 16] = T[0];
                Temp[(20 + Option.Length / 2) + 17] = T[1];
            }
            if(Protocol == "UDP")
            {
                byte[] Pseudo = GenPseudo();
                short Chksum = (short)basic.CheckSumEx(Pseudo, basic.HexStrToBytes(Data));
                List<byte> T = new List<byte>();
                T.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder(Chksum)));
                Temp[(20 + Option.Length / 2) + 6] = T[0];
                Temp[(20 + Option.Length / 2) + 7] = T[1];
            }
            return Temp.ToArray();
        }

        private byte [] GenPseudo()
        {
            List<byte> Temp = new List<byte>();

            Temp.AddRange(IPAddress.Parse(SrcIP).GetAddressBytes());
            Temp.AddRange(IPAddress.Parse(DstIP).GetAddressBytes());
            Temp.Add(0);
            Temp.Add((byte)ProtocolDic[Protocol]);
            Temp.AddRange(BitConverter.GetBytes((short)IPAddress.HostToNetworkOrder((short)(basic.RemoveSpace(Data).Length / 2))));
            return Temp.ToArray();
        }

        //private short 

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
