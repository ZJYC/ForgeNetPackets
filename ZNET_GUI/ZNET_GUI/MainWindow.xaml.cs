using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using PacketDotNet;
using System.Windows.Forms;
using PacketDotNet.Utils;
using SharpPcap.LibPcap;
using SharpPcap;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;

namespace ZNET_GUI
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        Basic basic = new Basic();
        SendNetPackets sendNetPackets = new SendNetPackets();
        Z_ETH_Packet z_ETH_Packet = new Z_ETH_Packet();
        Z_ARP_Packet z_ARP_Packet = new Z_ARP_Packet();
        

        private LibPcapLiveDeviceList Devices;
        private LibPcapLiveDevice Device;

        private IPAddress DeviceAddress;
        private PhysicalAddress DeviceMAC;

        private int GetTabItemIndex(string Header)
        {
            int Index = 0;
            try
            {
                foreach (TabItem Item in MainTable.Items)
                {
                    if ((string)Item.Header == Header)
                    {
                        return Index;
                    }
                    Index++;
                }
                throw new Exception("cant find the Item Header you needed...");
            }
            catch(Exception e)
            {

                System.Windows.Forms.MessageBox.Show(e.Message);
            }
            

            return 0;
        }

        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            using (System.Windows.Forms.OpenFileDialog openFileDialog = new System.Windows.Forms.OpenFileDialog())
            {
                openFileDialog.Filter = "pcap files (*.pcap)|*.pcap|All files (*.*)|*.*";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;
                if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    FilePathShow.Text = openFileDialog.FileName;
                }
                else
                {
                    FilePathShow.Text = "";
                }
            }
            
        }

        private void ARP_GenRep_Click(object sender, RoutedEventArgs e)
        {
            z_ARP_Packet.LocalMAC = PhysicalAddress.Parse(SenderMAC.Text).GetAddressBytes();
            z_ARP_Packet.LocalIP = IPAddress.Parse(SenderIP.Text).GetAddressBytes();
            z_ARP_Packet.DstMAC = PhysicalAddress.Parse(TargetMAC.Text).GetAddressBytes();
            z_ARP_Packet.DstIP = IPAddress.Parse(TargetIP.Text).GetAddressBytes();
            z_ARP_Packet.Opt = (string)ARP_OptCombox.SelectedValue;
            ArpPacketBytesShow.Text = basic.byteToHexStr(z_ARP_Packet.GenPacket());
        }

        private void GotoETH_Click(object sender, RoutedEventArgs e)
        {
            if (ArpPacketBytesShow.Text == "")
            {
                System.Windows.Forms.MessageBox.Show("No Data...");
                return;
            }
            ETH_UplayerData.Text = ArpPacketBytesShow.Text;
            MainTable.SelectedIndex = GetTabItemIndex("ETH");
            ETH_Combox.SelectedValue = "ARP";
        }

        private void ETH_Gen_Click(object sender, RoutedEventArgs e)
        {
            z_ETH_Packet.DstMAC = PhysicalAddress.Parse(ETH_RemoteMAC.Text).GetAddressBytes();
            z_ETH_Packet.SourceMAC = PhysicalAddress.Parse(ETH_LocalMAC.Text).GetAddressBytes();
            z_ETH_Packet.Type = (string)ETH_Combox.SelectedValue;
            z_ETH_Packet.Data = basic.HexStrToBytes(ETH_UplayerData.Text);
            ETH_PacketShow.Text = basic.byteToHexStr(z_ETH_Packet.GenPacket());
        }

        private void ETH_SaveToFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string LoadStr = ETH_PacketShow.Text.Replace(" ", "");
                byte[] LoadBytes = basic.HexStrToBytes(LoadStr);
                SimplePcapFile simplePcapFile = new SimplePcapFile();
                simplePcapFile.FileWrite(FilePathShow.Text, LoadBytes);
            }
            catch
            {
                System.Windows.Forms.MessageBox.Show("Error while write...");
                return;
            }
        }

        private void CreateNewFile_Click(object sender, RoutedEventArgs e)
        {
            Stream myStream;

            System.Windows.Forms.SaveFileDialog saveFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            
            saveFileDialog1.Filter = "pcap files (*.pcap)|*.pcap";
            saveFileDialog1.FilterIndex = 2;
            saveFileDialog1.RestoreDirectory = true;
            
            if (saveFileDialog1.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                if ((myStream = saveFileDialog1.OpenFile()) != null)
                {
                    //we must write the file header...
                    byte[] Data = { 0xD4,0xC3,0xB2,0xA1,
                        0x02,0x00,
                        0x04,0x00,
                        0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,
                        0x00,0xFF,0x00,0x00,
                        0x01,0x00,0x00,0x00,
                    };
                    myStream.Write(Data,0,Data.Length);
                    FilePathShow.Text = saveFileDialog1.FileName;
                    myStream.Close();
                }
            }
        }


        public string ETH_ComboxGet()
        {
            string str;

            if (ETH_Combox.SelectedIndex == 0)
            {
                str = "ARP";
            }
            else if (ETH_Combox.SelectedIndex == 1)
            {
                str = "XXX";
            }
            else if (ETH_Combox.SelectedIndex == 2)
            {
                str = "XXX";
            }
            else
            {
                str = "";
            }
            return str;
        }

        private void ComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

        }

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {
            ETH_Combox.SelectedIndex = 0;
            ETH_Combox.IsDropDownOpen = false;
        }

        private void MenuItem_Click_1(object sender, RoutedEventArgs e)
        {
            ETH_Combox.SelectedIndex = 1;
            ETH_Combox.IsDropDownOpen = false;
        }

        private void MenuItem_Click_2(object sender, RoutedEventArgs e)
        {
            ETH_Combox.SelectedIndex = 2;
            ETH_Combox.IsDropDownOpen = false;
        }

        private void BeginSelectInf_Click(object sender, RoutedEventArgs e)
        {
            Devices = LibPcapLiveDeviceList.Instance;

            if (Devices.Count < 1)
            {
                Config_Message.Content = "No devices were found on this machine";
                return;
            }
            List<string> ConfigComBoxItems = new List<string>();
            int i = 0;
            ConfigComBoxItems.Add("Select the interface here but me...");
            foreach (var dev in Devices)
            {
                if (dev.Interface.Addresses.Count == 0)
                {
                    ConfigComBoxItems.Add(i.ToString() + ":");
                }
                else
                {
                    ConfigComBoxItems.Add(i.ToString() + ":" + dev.Interface.FriendlyName + "@" +dev.Interface.Addresses[1].Addr);
                }
                i++;
            }
            ConfigComBox.ItemsSource = ConfigComBoxItems;
            ConfigComBox.SelectedIndex = 0;
        }

        private void ConfigComBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ConfigComBox.SelectedIndex <= 0) return;
            Device = Devices[ConfigComBox.SelectedIndex - 1];
            DeviceAddress = IPAddress.Parse(Device.Addresses[1].Addr.ToString());
            string str = basic.MacStringSplit(Device.Addresses[2].Addr.hardwareAddress.ToString());
            DeviceMAC = PhysicalAddress.Parse(str);
        }

        private void SetLocalIPMAC_Click(object sender, RoutedEventArgs e)
        {
            if((DeviceMAC != null) &&(DeviceAddress != null))
            {
                ETH_LocalMAC.Text = SenderMAC.Text = basic.MacStringSplit(DeviceMAC.ToString());
                SenderIP.Text = DeviceAddress.ToString();
            }
            else
            {
                System.Windows.Forms.MessageBox.Show("you should select one interface first and try again");
            }
        }

        private void ETH_GotoSender_Click(object sender, RoutedEventArgs e)
        {
            if(ETH_PacketShow.Text != "")
            {
                SenderDataShow.Text = ETH_PacketShow.Text;
                MainTable.SelectedIndex = GetTabItemIndex("Sender");
            }
            else
            {
                System.Windows.Forms.MessageBox.Show("No Data...");
            }
        }

        private void CHK_FromText_Checked(object sender, RoutedEventArgs e)
        {
            CHK_FromFile.IsChecked = false;
        }

        private void CHK_FromFile_Checked(object sender, RoutedEventArgs e)
        {
            CHK_FromText.IsChecked = false;
        }

        private void SendOut_Click(object sender, RoutedEventArgs e)
        {
            if(CHK_FromText.IsChecked == true)
            {
                sendNetPackets.SendPacketFromDataBox(Device, basic.HexStrToBytes(SenderDataShow.Text), SendTimingEn.IsChecked,int.Parse(SendPeriod.Text));
            }
            if (CHK_FromFile.IsChecked == true)
            {
                sendNetPackets.SendPacketsFromFile(Device, PacketsFileName.Text, SendTimingEn.IsChecked, int.Parse(SendPeriod.Text));
            }
        }

        private void OpenFileToSend_Click(object sender, RoutedEventArgs e)
        {
            using (System.Windows.Forms.OpenFileDialog openFileDialog = new System.Windows.Forms.OpenFileDialog())
            {
                openFileDialog.Filter = "pcap files (*.pcap)|*.pcap|All files (*.*)|*.*";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;
                if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    PacketsFileName.Text = openFileDialog.FileName;
                }
                else
                {
                    PacketsFileName.Text = "";
                }
            }
        }

        private void StopSend_Click(object sender, RoutedEventArgs e)
        {
            sendNetPackets.StopSend();
        }

        private void Table_IP_Initialized(object sender, EventArgs e)
        {
            List<string> IpUpProtocolComBox = new List<string> { "TCP","UDP" };
            IP_UPProtocol.ItemsSource = IpUpProtocolComBox;
        }

        private void ARP_GenReq_Copy1_Click(object sender, RoutedEventArgs e)
        {
            //检查数据
            try
            {
                UInt16.Parse(IP_SN.Text);
                if(UInt16.Parse(IP_Shift.Text) % 8 != 0)
                {
                    UInt16.Parse("");
                }
                byte.Parse(IP_TTL.Text);
                IPAddress.Parse(IP_DstIP.Text);
                IPAddress.Parse(IP_SourceIP.Text);
                if (basic.RemoveSpace(IP_OptionOrPad.Text).Length % 8 != 0) UInt16.Parse("");
                if (basic.RemoveSpace(IP_Data.Text).Length % 2 != 0) UInt16.Parse("");
            }
            catch
            {
                System.Windows.MessageBox.Show("参数不对");
                return;
            }

            JX_IP_Packet jX_IP_Packet = new JX_IP_Packet();
            jX_IP_Packet.ID = IP_SN.Text;
            jX_IP_Packet.DF = IP_DF.IsChecked;
            jX_IP_Packet.MF = IP_MF.IsChecked;
            jX_IP_Packet.Shift = IP_Shift.Text;
            jX_IP_Packet.DstIP = IP_DstIP.Text;
            jX_IP_Packet.SrcIP = IP_SourceIP.Text;
            jX_IP_Packet.TTL = IP_TTL.Text;
            jX_IP_Packet.Protocol = (string)IP_UPProtocol.SelectedValue;
            jX_IP_Packet.Option = IP_OptionOrPad.Text;
            jX_IP_Packet.Data = IP_Data.Text;

            IP_PacketShow.Text = basic.byteToHexStr(jX_IP_Packet.GenPacket());

        }

        private void Table_ETH_Initialized(object sender, EventArgs e)
        {
            List<string> ListETH_Combox = new List<string>() {"ARP","IP" };
            ETH_Combox.ItemsSource = ListETH_Combox;
        }

        private void TabItem_Initialized(object sender, EventArgs e)
        {
            List<string> ComboxItemSource = new List<string>() { "Request", "Reply" };
            ARP_OptCombox.ItemsSource = ComboxItemSource;
        }

        private void IP_GotoETH_Click(object sender, RoutedEventArgs e)
        {
            if(IP_PacketShow.Text == "")
            {
                System.Windows.Forms.MessageBox.Show("No Data...");
                return;
            }
            ETH_Combox.SelectedValue = "IP";
            ETH_UplayerData.Text = IP_PacketShow.Text;
            MainTable.SelectedIndex = GetTabItemIndex("ETH");
        }

        private void TCP_GenPacket_Click(object sender, RoutedEventArgs e)
        {
            /* 检查数据 */
            try
            {
                UInt16 Temp16 = 0;
                UInt32 Temp32 = 0;
                Temp16 = UInt16.Parse(TCP_SourcePort.Text);
                Temp16 = UInt16.Parse(TCP_DstPort.Text);
                Temp16 = UInt16.Parse(TCP_WinSize.Text);
                Temp16 = UInt16.Parse(TCP_UrgPointer.Text);
                Temp32 = UInt32.Parse(TCP_SNNum.Text);
                Temp32 = UInt32.Parse(TCP_ACKNum.Text);
                if(TCP_DataInput.Text != "")
                {
                    byte[] TempArray1 = basic.HexStrToBytes(TCP_DataInput.Text);
                }
                if (TCP_OptionInput.Text != "")
                {
                    byte[] TempArray2 = basic.HexStrToBytes(TCP_OptionInput.Text);
                }
                if (basic.RemoveSpace(TCP_DataInput.Text).Length % 2 != 0 || basic.RemoveSpace(TCP_OptionInput.Text).Length % 8 != 0)
                {
                    System.Windows.MessageBox.Show("数据或选项字段长度非法");
                    return;
                }
            }
            catch
            {
                System.Windows.MessageBox.Show("输入数据非法");
                return;
            }
            Z_TCP_Packet z_TCP_Packet = new Z_TCP_Packet();
            z_TCP_Packet.Data = TCP_DataInput.Text;
            z_TCP_Packet.Option = TCP_OptionInput.Text;
            z_TCP_Packet.SrcPort = TCP_SourcePort.Text;
            z_TCP_Packet.DstPort = TCP_DstPort.Text;
            z_TCP_Packet.SnNum = TCP_SNNum.Text;
            z_TCP_Packet.AcNum = TCP_ACKNum.Text;
            z_TCP_Packet.WinSize = TCP_WinSize.Text;
            z_TCP_Packet.UrgPointer = TCP_UrgPointer.Text;
            z_TCP_Packet.CWR = TCP_F_CWR.IsChecked;
            z_TCP_Packet.ECE = TCP_F_ECE.IsChecked;
            z_TCP_Packet.URG = TCP_F_URG.IsChecked;
            z_TCP_Packet.ACK = TCP_F_ACK.IsChecked;
            z_TCP_Packet.PSH = TCP_F_PSH.IsChecked;
            z_TCP_Packet.RST = TCP_F_RST.IsChecked;
            z_TCP_Packet.SYN = TCP_F_SYN.IsChecked;
            z_TCP_Packet.FIN = TCP_F_FIN.IsChecked;
            TCP_Packet.Text = basic.byteToHexStr(z_TCP_Packet.GenPacket());

        }

        private void TCP_SendToIP_Click(object sender, RoutedEventArgs e)
        {
            if(TCP_Packet.Text == "")
            {
                System.Windows.MessageBox.Show("没有数据啊");
                return;
            }
            IP_UPProtocol.SelectedValue = "TCP";
            IP_Data.Text = TCP_Packet.Text;
            MainTable.SelectedIndex = GetTabItemIndex("IP");
        }

        private void GenUDPPacket_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ushort.Parse(UDP_SrcPort.Text);
                ushort.Parse(UDP_DstPort.Text);
                if (basic.RemoveSpace(UDP_Data.Text).Length % 2 == 1) int.Parse("");
            }
            catch
            {
                System.Windows.MessageBox.Show("数据输入不对");
                return;
            }
            Z_UDP_Packet z_UDP_Packet = new Z_UDP_Packet();
            z_UDP_Packet.Data = UDP_Data.Text;
            z_UDP_Packet.DstPort = UDP_DstPort.Text;
            z_UDP_Packet.SrcPort = UDP_SrcPort.Text;

            UDP_Packet.Text = basic.byteToHexStr(z_UDP_Packet.GenPacket());
        }

        private void UDPGotoIPLayer_Click(object sender, RoutedEventArgs e)
        {
            if (UDP_Packet.Text == "")
            {
                System.Windows.MessageBox.Show("没有数据啊");
                return;
            }
            IP_UPProtocol.SelectedValue = "UDP";
            IP_Data.Text = UDP_Packet.Text;
            MainTable.SelectedIndex = GetTabItemIndex("IP");
        }
    }
}
