using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.WinPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using System.Threading;


namespace ZNET_GUI
{
    class SendNetPackets
    {
        Basic basic = new Basic();
        public bool SendingThreadEnable = true;

        public ICaptureDevice OpenPacketsFile(string PacketFileName)
        {
            try
            {
                ICaptureDevice PacketsFile = new CaptureFileReaderDevice(PacketFileName);
                PacketsFile.Open();
                return PacketsFile;
            }
            catch
            {
                basic.MessageBox("Error:PacketsFile");
            }
            return null;
        }

        public void SendPacketsFromFile(LibPcapLiveDevice Device, string Path, bool? PeriodEn, int Period)
        {
            Device.Open();
            SendingThreadEnable = true;

            List<RawCapture> rawCaptures = new List<RawCapture>();

            try
            {
                RawCapture packet;
                ICaptureDevice PacketsFile = OpenPacketsFile(Path);
                while ((packet = PacketsFile.GetNextPacket()) != null)
                {
                    rawCaptures.Add(packet);
                }
            }
            catch (Exception e)
            {
                basic.MessageBox(e.Message);
            }

            Thread td = new Thread(() =>
            {
                while (true)
                {
                    if (SendingThreadEnable == false) break;
                    
                    try
                    {
                        for(int i = 0;i < rawCaptures.Count;i ++)
                        {
                            Device.SendPacket(rawCaptures[i].Data);
                        }
                    }
                    catch (Exception e)
                    {
                        basic.MessageBox(e.Message);
                    }
                    if (PeriodEn == true)
                    {
                        Thread.Sleep(Period);
                    }
                    else
                    {
                        break;
                    }
                }
            });
            td.Start();
        }

        public void SendPacketFromDataBox(LibPcapLiveDevice Device, byte [] Packt, bool? PeriodEn, int Period)
        {
            Device.Open();
            SendingThreadEnable = true;
            Thread td = new Thread(() =>
            {
                while (true)
                {
                    if (SendingThreadEnable == false) break;
                    try
                    {
                        Device.SendPacket(Packt);
                    }
                    catch
                    {
                        break;
                    }
                    if (PeriodEn == true)
                    {
                        Thread.Sleep(Period);
                    }
                    else
                    {
                        break;
                    }
                }
            });
            td.Start();
        }

        public void StopSend()
        {
            SendingThreadEnable = false;
        }

    }
}
