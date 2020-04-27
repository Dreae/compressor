## Compressor
Compressor is primarily an [eBPF](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter#Extensions_and_optimizations) [XDP](https://en.wikipedia.org/wiki/Express_Data_Path)
program that forwards traffic from an edge server running linux to a game server running Source engine games.
Compressor is most useful for an anycast configuration where multiple edge servers running compressor are 
forwarding to your game servers.

### Setup
#### Building
For building compressor you'll need a reasonably recent kernel version (>4.18), as well as the following dependencies
- libhiredis
- libconfig
- libevent
- libelf
- llvm
- kernel-headers
Additionally, because compressor is a eBPF you'll need a recent version of clang to compile the C code into eBPF bytecode.
On ubuntu this can be installed with
```bash
root@compressor:~# apt install build-essential clang llvm libconfig-dev libhiredis-dev libelf-dev libevent-dev
```
Once the dependencies are installed you'll need to clone and build compressor:
```bash
root@compressor:~# git clone --recursive https://gitlab.com/Dreae/compressor.git
root@compressor:~# cd compressor
root@compressor:~/compressor# make && make install
```

#### Configuration
After compressor is built you'll need to add all of your game servers to the compressor configuration located at `/etc/compressor/compressor.conf`.
An example configuration is provided, the main body of the configuration is the `srcds` array, which contains the configuration objects for
each of your srcds instance. Each object consists of a `bind` and `dest` address, the bind address is the address that compressor should
listen for incoming traffic on, usually the IP of the instance running compressor, or an anycast address. The `dest` address is the address
where incoming srcds traffic should be forwarded, usually the IP address of the game server. Compressor also supports setting an `internal_ip`
which will be the destination IP on the internal IP-in-IP packet, this is useful for more advanced routing.

Once all of the servers are added to the compressor configuration you simply need to run the compressor binary, installed by default at
`/usr/bin/compressor`. It is advisable to install compressor as a system service so that it will be automatically started with the system.

#### Configuring the Game Server
Compressor sends all traffic it receives to the game server in an IP-in-IP tunnel, and forwards all traffic it receives from the game server
side of the tunnel out to the internet. This means your game server will need to be configured to route all traffic through an IPIP tunnel.
On linux this can be accomplished using network namespaces and the built-in IPIP tunnel.

The first step is to create the IPIP tunnel interface
```bash
root@gameserver:~# ip tunnel add compressor mode ipip remote <compressor address>
```
This should create an IPIP tunnel named `compressor` in your network interfaces.
```bash
4: compressor@NONE <POINTTOPOINT,NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ipip 0.0.0.0 peer <compressor address>
```

Once the IPIP tunnel is created, you'll need to create the net namespace, and configure the tunnel to be the default interface inside the namespace.
```bash
root@gameserver:~# ip netns add compressorns
root@gameserver:~# ip link set compressor netns compressorns
```
These commands will create a network namespace named `compressorns` and move the `compressor` tunnel interfaces into this namespace. After that you will need to
configure the tunnel interface as the default interface in the namespace.
```bash
root@gameserver:~# ip netns exec compressorns ip addr add <gameserver address> dev compressor
root@gameserver:~# ip netns exec compressorns ip link set compressor up
root@gameserver:~# ip netns exec compressorns ip route add default dev compressor
```

Finally you will need to set the DNS servers for the gameserver to something accessible from the internet, such as Cloudflare's DNS
```bash
root@gameserver:~# printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1' > /etc/resolv.conf
```

After completing these steps you should be able run srcds inside the namespace, and all traffic will be routed through compressor.
```bash
steamcmd@gameserver:~# ip netns exec compressorns ./srcds_run -game cstrike +map cs_office +sv_lan 0
```
In the output you should see
```bash
Public IP is <compressor IP>
```

#### Notes About Anycast
If you have configured your network for anycast, simply replace all occurances of `<compressor ip>` in the above with the anycast address you wish
the game server to use. Note, however, that this means that all outgoing traffic from the game server on the tunnel will be routed to the nearest
anycast node. Additionally, for `A2S_INFO` caching to work with an anycast setup, you will need an additional server to act as the cache, which all
anycast nodes will fetch the cached `A2S_INFO` packets from. Compressor supports using either redis or [Cockpit](https://gitlab.com/Dreae/cockpit)
as the cache server. Redis is the most straightforward configuration, simply add the `redis_cache` object to the toplevel compressor configuration
to point to the redis server you wish to use:
```
interface "eth0";
redis_cache = {
  address = "a.b.c.d"
  port = 6379
};
```
Note that all anycast nodes *MUST* use the same redis server for `A2S_INFO` caching to work.

[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/thedreae)
