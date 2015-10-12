require 'packetfu'

USAGE_STRING = "Usage: #{$0} [-r] [logfile_path]"

$vul_num = 0
#{incident_number}. ALERT: #{incident} is detected from #{source IP address} (#{protocol}) (#{payload})!

# SOURCE: http://snippets.aktagon.com/snippets/335-how-to-parse-apache-logs-with-ruby
class ApacheLog
  FORMATS = {
    :combined => %r{^(\S+) - - \[(\S+ \+\d{4})\] "(\S+ \S+ [^"]+)" (\d{3}) (\d+|-) "(.*?)" "([^"]+)"$}
  }
  
  class << self
    def each_line(log_file, log_format = FORMATS[:combined])

      f = File.open(log_file, "r")

      f.each_line do|line|
        data = line.scan(log_format).flatten

        if data.empty?
          p "Line didn't match pattern: #{line}"

          next
        end

        yield data
      end
    end
  end
end

def alert(vul, info, proto)
	puts "#{$vul_num}. ALERT: #{vul} is deteced from #{info.ip} (#{proto}) (#{info.payload})!"
	$vul_num += 1
end

def live_scan()
	stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	# stream.show_live()

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

		# TODO: check other Nmap scans
		if (pkt.payload =~ /Nmap/)
			alert("Other Nmap scan", pkt, protocol[-1])
		end

		# TODO: check Nikto scans
		if (pkt.payload =~ /Nikto/)
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
	# TODO: Q: is HTTP always the protocol for log files
	# TODO: Q: do i need quotes for the payload ("GET HTTP/afjkafj/") vs (GET HTTPS/asfsa/fsa)
	ApacheLog.each_line(file) do |data|
		host, date, url_with_method, status, size, referrer, agent = data
	# TODO: 
		# NMAP scan (of any variety)
		if (data =~ /Nmap/)
			alert("Nmap scan", LogInfo.new(host, url_with_method), "HTTP")
		# Nikto scan
		elsif (data =~ /Nikto/)
			alert("Nikto scan", LogInfo.new(host, url_with_method), "HTTP")
		# Someone running Rob Graham's Masscan
		# Someone scanning for Shellshock vulnerability.
		# Anything pertaining to phpMyAdmin
		# Anything that looks like shellcode.
		end
	end

end

if (ARGV[0] == "-r")
	puts "WEB LOG ANALYZER "
	LogInfo = Struct.new(:ip, :payload)

	if (ARGV[1] == nil)
		puts USAGE_STRING
		exit(1)
	end

	log_scan(ARGV[1])
else
	puts "LIVE SCAN"
	live_scan()
end