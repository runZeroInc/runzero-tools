#!/usr/bin/env ruby

#
# Extract URLs from a runZero Asset Export (JSONL format)
#

require 'json'

$stdin.each_line do |line|
    asset = JSON.parse(line.strip)
    asset['services'].each_pair do |n,s|
        next if s['protocol'] != "http"
        addr,port,sname = n.split("/")
        if s.keys.include?("tls.cipher")
            puts "https://#{addr}:#{port}"
        else 
            puts "http://#{addr}:#{port}"
        end
    end
end