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

        GeneratePackets GenPackets = new GeneratePackets();
        Basic basic = new Basic();
        SendNetPackets sendNetPackets = new SendNetPackets();

        private string LastPcapFilePath = "c:\\";
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
                    LastPcapFilePath = openFileDialog.FileName;
                }
                else
                {
                    FilePathShow.Text = "";
                }
            }
            
        }

        private void ARP_GenReq_Click(object sender, RoutedEventArgs e)
        {
            ArpPacket ArpReqPacket = GenPackets.GetArpPacketFromGUI(
                ArpOperation.Request,
                TargetMAC.Text,
                TargetIP.Text,
                SenderMAC.Text,
                SenderIP.Text);
            ArpPacketBytesShow.Text = basic.byteToHexStr(ArpReqPacket.Bytes);
        }

        private void ARP_GenRep_Click(object sender, RoutedEventArgs e)
        {
            ArpPacket ArpReqPacket = GenPackets.GetArpPacketFromGUI(
                ArpOperation.Response,
                TargetMAC.Text,
                TargetIP.Text,
                SenderMAC.Text,
                SenderIP.Text);
            ArpPacketBytesShow.Text = basic.byteToHexStr(ArpReqPacket.Bytes);
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
            ETH_ComboxSet("ARP");
            //Table_ETH.RaiseEvent(new RoutedEventArgs(TabItem.GotFocusEvent));

        }

        private void ETH_Gen_Click(object sender, RoutedEventArgs e)
        {
            EthernetPacket ethernetPacket = GenPackets.GetEthPacketFromGUI(ETH_ComboxGet(),ETH_LocalMAC.Text, ETH_RemoteMAC.Text);
            string LoadStr = ETH_UplayerData.Text.Replace(" ","");
            byte[] LoadBytes = basic.HexStrToBytes(LoadStr);
            ethernetPacket.PayloadData = LoadBytes;
            ETH_PacketShow.Text = basic.byteToHexStr(ethernetPacket.Bytes);
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
        public void ETH_ComboxSet(string str)
        {
            if(str == "ARP")
            {
                ETH_Combox.SelectedIndex = 0;
            }
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
                    LastPcapFilePath = openFileDialog.FileName;
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

        private void IP_AutoFill_Click(object sender, RoutedEventArgs e)
        {
            #region 如果没有填充，则会自动填充
            if (IP_Version.Text == "") IP_Version.Text = "4";
            if(IP_HeaderLen.Text == "")
            {
                ;
            }
            if (IP_ServiceType.Text == "") IP_ServiceType.Text = "0";
            if(IP_TotolLen.Text == "")
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
            IP_Packet iP_Packet = new IP_Packet();
            iP_Packet.Version = byte.Parse(IP_Version.Text);
            iP_Packet.ServiceID = byte.Parse(IP_ServiceType.Text);
            iP_Packet.SN = UInt16.Parse(IP_SN.Text);
            iP_Packet.DF = IP_DF.IsChecked;
            iP_Packet.MF = IP_MF.IsChecked;
            iP_Packet.Shift = UInt16.Parse(IP_Shift.Text);
            iP_Packet.TTL = byte.Parse(IP_TTL.Text);
            UInt16 Value = 0;
            iP_Packet.ProtocolDic.TryGetValue((string)IP_UPProtocol.SelectedValue, out Value);
            iP_Packet.Protocol = (byte)Value;//iP_Packet.ProtocolDic(IP_UPProtocol.);
            iP_Packet.SourceIP = IP_SourceIP.Text;
            iP_Packet.DstIP = IP_DstIP.Text;
            iP_Packet.OptionPad = IP_OptionOrPad.Text;
            iP_Packet.Data = IP_Data.Text;
            iP_Packet.HeaderLen = byte.Parse(IP_HeaderLen.Text);
            iP_Packet.TotolLen = UInt16.Parse(IP_TotolLen.Text);
            iP_Packet.Chksum = Convert.ToUInt16(IP_Chksum.Text,16);
            IP_PacketShow.Text = basic.byteToHexStr(iP_Packet.GenPacket());
            #endregion

            #region 将计算结果显示回来
            //byte Version { get; set; }
            //byte HeaderLen { get; set; }
            //byte ServiceID { get; set; }
            //UInt16 TotolLen { get; set; }
            //UInt16 SN { get; set; }
            //bool DF { get; set; }
            //bool MF { get; set; }
            //UInt16 Shift { get; set; }
            //byte TTL { get; set; }
            //byte Protocol { get; set; }
            //UInt16 Chksum { get; set; }
            //string SourceIP { get; set; }
            //string DstIP { get; set; }
            //string OptionPad { get; set; }
            //string Data { get; set; }
            IP_HeaderLen.Text = iP_Packet.HeaderLen.ToString();
            IP_TotolLen.Text = iP_Packet.TotolLen.ToString();
            IP_Chksum.Text = string.Format("{0:X}", iP_Packet.Chksum);
            #endregion
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
            IP_Packet iP_Packet = new IP_Packet();
            iP_Packet.Version = byte.Parse(IP_Version.Text);
            iP_Packet.ServiceID = byte.Parse(IP_ServiceType.Text);
            iP_Packet.SN = UInt16.Parse(IP_SN.Text);
            iP_Packet.DF = IP_DF.IsChecked;
            iP_Packet.MF = IP_MF.IsChecked;
            iP_Packet.Shift = UInt16.Parse(IP_Shift.Text);
            iP_Packet.TTL = byte.Parse(IP_TTL.Text);
            UInt16 Value = 0;
            iP_Packet.ProtocolDic.TryGetValue((string)IP_UPProtocol.SelectedValue, out Value);
            iP_Packet.Protocol = (byte)Value;//iP_Packet.ProtocolDic(IP_UPProtocol.);
            iP_Packet.SourceIP = IP_SourceIP.Text;
            iP_Packet.DstIP = IP_DstIP.Text;
            iP_Packet.OptionPad = IP_OptionOrPad.Text;
            iP_Packet.Data = IP_Data.Text;
            iP_Packet.HeaderLen = byte.Parse(IP_HeaderLen.Text);
            iP_Packet.TotolLen = UInt16.Parse(IP_TotolLen.Text);
            iP_Packet.Chksum = Convert.ToUInt16(IP_Chksum.Text,16);
            IP_PacketShow.Text = basic.byteToHexStr(iP_Packet.GenPacket());
            #endregion

            #region 将计算结果显示回来
            IP_HeaderLen.Text = iP_Packet.HeaderLen.ToString();
            IP_TotolLen.Text = iP_Packet.TotolLen.ToString();
            IP_Chksum.Text = string.Format("{0:X}", iP_Packet.Chksum);
            #endregion
        }

        private void IP_ClearAuto_Click(object sender, RoutedEventArgs e)
        {
            IP_HeaderLen.Text = "0";
            IP_TotolLen.Text = "0";
            IP_Chksum.Text = "0";
        }
    }
}
