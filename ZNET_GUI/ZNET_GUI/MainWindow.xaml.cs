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
        ZJ_IP_Packet zJ_IP_Packet = new ZJ_IP_Packet();

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
            #region 如果没有填充，则会自动填充
            if (IP_Version.Text == "") IP_Version.Text = "4";
            if (IP_HeaderLen.Text == "")
            {
                ;
            }
            if (IP_ServiceType.Text == "") IP_ServiceType.Text = "0";
            if (IP_TotolLen.Text == "")
            {
                ;
            }
            if (IP_SN.Text == "") IP_SN.Text = "1234";
            if (IP_Shift.Text == "") IP_Shift.Text = "0";
            if (IP_TTL.Text == "") IP_TTL.Text = "64";
            if (IP_UPProtocol.SelectedIndex == -1) IP_UPProtocol.SelectedIndex = 0;
            if (IP_Chksum.Text == "")
            {
                ;
            }
            if (IP_OptionOrPad.Text == "") IP_OptionOrPad.Text = "";
            #endregion

            #region 部分字段需要计算
            zJ_IP_Packet.Version = byte.Parse(IP_Version.Text);
            zJ_IP_Packet.ServiceID = byte.Parse(IP_ServiceType.Text);
            zJ_IP_Packet.SN = UInt16.Parse(IP_SN.Text);
            zJ_IP_Packet.DF = IP_DF.IsChecked;
            zJ_IP_Packet.MF = IP_MF.IsChecked;
            zJ_IP_Packet.Shift = UInt16.Parse(IP_Shift.Text);
            zJ_IP_Packet.TTL = byte.Parse(IP_TTL.Text);
            UInt16 Value = 0;
            zJ_IP_Packet.ProtocolDic.TryGetValue((string)IP_UPProtocol.SelectedValue, out Value);
            zJ_IP_Packet.Protocol = (byte)Value;//iP_Packet.ProtocolDic(IP_UPProtocol.);
            zJ_IP_Packet.SourceIP = IP_SourceIP.Text;
            zJ_IP_Packet.DstIP = IP_DstIP.Text;
            zJ_IP_Packet.OptionPad = IP_OptionOrPad.Text;
            zJ_IP_Packet.Data = IP_Data.Text;
            zJ_IP_Packet.HeaderLen = byte.Parse(IP_HeaderLen.Text);
            zJ_IP_Packet.TotolLen = UInt16.Parse(IP_TotolLen.Text);
            zJ_IP_Packet.Chksum = Convert.ToUInt16(IP_Chksum.Text,16);
            IP_PacketShow.Text = basic.byteToHexStr(zJ_IP_Packet.GenPacket());
            #endregion

            #region 将计算结果显示回来
            IP_HeaderLen.Text = zJ_IP_Packet.HeaderLen.ToString();
            IP_TotolLen.Text = zJ_IP_Packet.TotolLen.ToString();
            IP_Chksum.Text = string.Format("{0:X}", zJ_IP_Packet.Chksum);
            #endregion
        }

        private void IP_ClearAuto_Click(object sender, RoutedEventArgs e)
        {
            IP_HeaderLen.Text = "0";
            IP_TotolLen.Text = "0";
            IP_Chksum.Text = "0";
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
    }
}
