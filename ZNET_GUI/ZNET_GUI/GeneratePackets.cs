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
