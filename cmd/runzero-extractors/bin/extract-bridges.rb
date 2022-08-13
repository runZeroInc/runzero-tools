#!/usr/bin/env ruby

#
# Extract critical network bridges from a runZero Asset Export (JSONL format)
#

require 'json'
require 'ipaddr'

def checkNetworks(nets, a)
    addr = IPAddr.new(a).to_i
    nets.each do |net|
        begAddr = net.to_range.first.to_i
        endAddr = net.to_range.last.to_i
        if addr >= begAddr && addr <= endAddr
            return true
        end
    end
    return false
end

defaultSize  = 24

criticalNets = []
ARGV.each do |net|
    criticalNets.push IPAddr.new(net)
end

if criticalNets.length == 0 
    $stderr.puts "usage: ./extract-bridges.rb [critical-net/24].. [critical-net/24].. < assets.jsonl"
    exit(0)
end

$stdin.each_line do |line|
    asset = JSON.parse(line.strip)
    netCrit = []
    netNonCrit = []
    addrs = asset['addresses'] + asset['addresses_extra']
    addrs.each do |a|
        # Skip IPv6 for now
        next if a.include?(":")

        # Create a network of the default mask size
        c = checkNetworks(criticalNets, a)
        if c
            netCrit.push(a)
        else 
            netNonCrit.push(a)
        end
    end

    if netCrit.length > 0 and netNonCrit.length > 0
        $stdout.puts " * #{asset['addresses'][0]} bridges non-critical networks (#{netNonCrit.join(", ")}) to critical networks via #{netCrit.join(", ")}\n\n"
    end
end
