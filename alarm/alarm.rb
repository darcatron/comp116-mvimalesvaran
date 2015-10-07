require 'packetfu'

vul_num = 0
#{incident_number}. ALERT: #{incident} is detected from #{source IP address} (#{protocol}) (#{payload})!
def alert(vul, pkt, proto)
	puts vul_num + ". ALERT: " + vul + " is deteced from " + pkt.ip + '(' + proto + ')' + '(' + pkt.payload + ")!"
	vul_num += 1
end

stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
# stream.show_live()

stream.stream.each do |p|
	pkt = PacketFu::Packet.parse p
	protocol = pkt.proto

	# check TCP scans
	if (protocol.include? "TCP")
		flags = pkt.tcp_flags
		if (flags.urg == 0 && flags.ack == 0 && flags.psh == 0 && flags.rst == 0 && flags.syn == 0 && flags.fin == 0)
			alert("NULL scan", pkt, "TCP")
		end
		if (flags.urg == 0 && flags.ack == 0 && flags.psh == 0 && flags.rst == 0 && flags.syn == 0 && flags.fin == 1)
			alert("FIN scan", pkt, "TCP")
		end
		if (flags.urg == 1 && flags.ack == 0 && flags.psh == 1 && flags.rst == 0 && flags.syn == 0 && flags.fin == 1)
			alert("XMAS scan", pkt, "TCP")
		end
	end

	# check other Nmap scans
	if (pkt.payload =~ /Nmap/)
		alert("Other Nmap scan", pkt, protocol[-1])
	end

	# check Nikto scans
	if (pkt.payload =~ /Nikto/)
		alert("Nikto scan", pkt, protocol[-1])
	end

	# check for credit car numbers Vis
	if (pkt.payload =~ /\d{4}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ ||
		pkt.payload =~ /\d{4}(\s|-)?\d{6}(\s|-)?\d{5}/)
		alert("Credit card leak", pkt, protocol[-1])
	end
end