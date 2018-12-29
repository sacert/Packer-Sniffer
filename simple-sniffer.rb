require 'packetfu'
require 'pry-byebug'
require 'resolv'

puts "Simple sniffer for PacketFu #{PacketFu.version}"
include PacketFu
iface = ARGV[0] || PacketFu::Utils.default_int
local_address =  PacketFu::Utils.whoami?[:ip_saddr]


def get_hostname(ip_address)
  hostname = ""
  begin
    hostname = Resolv.getname(ip_address.to_s)
  rescue
    hostname = ip_address.to_s
  end
end

def sniff(iface, local_address)
  cap = Capture.new(:iface => iface, :start => true)
  cap.stream.each do |p|
    pkt = Packet.parse p
    if pkt.is_ip?
      next if pkt.ip_saddr == Utils.ifconfig(iface)[:ip_saddr]
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      if pkt.is_tcp? && (pkt.tcp_src == 443 || pkt.tcp_dst == 80 || pkt.tcp_src == 80 || pkt.tcp_dst == 443) 
        dst_name = get_hostname pkt.ip_daddr
        src_name = get_hostname pkt.ip_saddr
        print pkt.tcp_src.to_s + " " + pkt.tcp_dst.to_s + " " + src_name + " " + dst_name + "\n"
      end
      #puts "%-15s -> %-15s %-4d %s" % packet_info
    end
  end
end

sniff(iface, local_address)
