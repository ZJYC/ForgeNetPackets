# ForgeNetPackets

If you want to forge some Network Packets to do some 
interesting thing.But you dont want to program with 
youself,You can try this.
while I can only forge ARP packetnow,The new functiong 
will show up in the future.. 

基于 PacketDotNet.0.30.2 和 SharpPcap.4.6.1写的伪造数据包的程序。

伪造的数据包可以保存在pcap文件中，可以用wireshark检查。

后期会有程序读取pcap文件并发送（还在开发中...お待ってください）

ARP攻击原理：
原因有二：
1、ARP没有严格的状态机，至少多数如此。
向其发送请求包，他会将请求包里的信息自动记录到缓存，这就实现了
污染缓存表的目的。或者向其发送应答包（我没试过）
2、几乎不进行跨层别检查：也就是ARP层不会检查ETH层的内容。
我们可以实现单播，局域网其他机器吃瓜就行。
最后：你要是攻击电脑会被发现的，电脑一般都有ARP防火墙，对于电脑
只能攻击路由，污染路由的缓存表，而且频率要快一些，因为电脑比
手机的反应速度快很多。





