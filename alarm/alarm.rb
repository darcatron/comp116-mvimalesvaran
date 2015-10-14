require 'packetfu'
require 'rubygems'
# SOURCE: http://simonecarletti.com/blog/2009/02/apache-log-regex-a-lightweight-ruby-apache-log-parser/
require 'apachelogregex'
require 'date'

USAGE_STRING = "Usage: #{$0} [-r] [logfile_path]"

$vul_num = 0

def alert(vul, info, proto)
	puts "#{$vul_num}. ALERT: #{vul} is deteced from #{info.ip} (#{proto}) (#{info.payload})!"
	$vul_num += 1
end

def live_scan()
	stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)

	stream.stream.each do |p|
		pkt = PacketFu::Packet.parse p
		protocol = pkt.proto

		# check TCP scans
		if (protocol.include? "TCP")
			flags = pkt.tcp_flags
			
			# check NULL scan
			if (flags.urg == 0 && flags.ack == 0 && flags.psh == 0 && flags.rst == 0 && flags.syn == 0 && flags.fin == 0)
				alert("NULL scan", pkt, "TCP")
			end
			
			# check FIN scan
			if (flags.urg == 0 && flags.ack == 0 && flags.psh == 0 && flags.rst == 0 && flags.syn == 0 && flags.fin == 1)
				alert("FIN scan", pkt, "TCP")
			end

			# check XMAS scan
			if (flags.urg == 1 && flags.ack == 0 && flags.psh == 1 && flags.rst == 0 && flags.syn == 0 && flags.fin == 1)
				alert("XMAS scan", pkt, "TCP")
			end
		end
		

		# check other Nmap scans
		if (not pkt.payload.scan(/\x4e\x6d\x61\x70/).empty? || pkt.payload =~ /Nmap/)
			alert("Other Nmap scan", pkt, protocol[-1])
		end

		# check Nikto scans
		if (not pkt.payload.scan(/\x4e\x69\x6b\x74\x6f/).empty? || pkt.payload =~ /Nikto/)
			alert("Nikto scan", pkt, protocol[-1])
		end

		# check for credit card numbers 
		# AmEx has different format for 15 digits
		if (pkt.payload =~ /\d{4}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/ ||
			pkt.payload =~ /\d{4}(\s|-)?\d{6}(\s|-)?\d{5}/)
			alert("Credit card leak", pkt, protocol[-1])
		end
	end
end

def log_scan(file)
	format = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"'
	parser = ApacheLogRegex.new(format)

	File.readlines(file).collect do |line|
	  	data = parser.parse line

		# NMAP scan (of any variety)
		if (line =~ /Nmap/)
			alert("Nmap scan", LogInfo.new(data['%h'], data['%r']), "HTTP")
		# Nikto scan
		elsif (line =~ /Nikto/)
			alert("Nikto scan", LogInfo.new(data['%h'], data['%r']), "HTTP")
		# Someone running Rob Graham's Masscan
		elsif (line =~ /Masscan/)
			alert("Masscan", LogInfo.new(data['%h'], data['%r']), "HTTP")
		# Someone scanning for Shellshock vulnerability.
		elsif (line =~ /{ :;}/)
			alert("Shellshock", LogInfo.new(data['%h'], data['%r']), "HTTP")
		# Anything pertaining to phpMyAdmin
		elsif (line =~ /phpMyAdmin/)
			alert("phpMyAdmin", LogInfo.new(data['%h'], data['%r']), "HTTP")
		# Anything that looks like shellcode.
		elsif (line =~ /\\x/)
			alert("Shellcode", LogInfo.new(data['%h'], data['%r']), "HTTP")
		end
	end

end

if (ARGV[0] == "-r")
	if (ARGV[1] == nil)
		puts USAGE_STRING
		exit(1)
	end

	LogInfo = Struct.new(:ip, :payload)

	puts "Starting Web Log Analyzer..."
	log_scan(ARGV[1])
else
	puts "Starting Live Scan..."
	live_scan()
end