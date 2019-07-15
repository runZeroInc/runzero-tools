#!/usr/bin/env ruby

#
# Extract URLs from a Rumble Asset Export (JSON)
#

require 'json'

assets = JSON.parse($stdin.read)
assets.each do |asset|
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