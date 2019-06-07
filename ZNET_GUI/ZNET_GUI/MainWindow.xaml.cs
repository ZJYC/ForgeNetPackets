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
        private string LastPcapFilePath = "c:\\";

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
    }
}
