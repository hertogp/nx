#! /usr/bin/env lua

-- TODO: howto automatically find nx/cmd.lua modules
package.path = package.path .. ';/home/pdh/dev/nx/src/?.lua'
--[[-- helpers --]]

local dump = require 'dump'
local sf = string.format

--[[-- argparse --]]
local argparse = require 'argparse'
local parser = argparse() {
  name = 'nx',
  description = 'get some info from the net',
  epilog = 'for more info see https://github.com/hertogp/nx',
}

-- collect parser:command's
parser:command_target('command')

--[[-- commands --]]
local tst = parser:command 'tst' {
  name = 'test',
  description = 'playing around',
}
tst:argument('name')
tst:argument('rrtype'):args('?')

-- Certificate listing
local crt = parser:command 'crt' {
  name = 'cert',
  description = 'get certificate information',
  epilog = 'for more info see https://github.com/hertogp/nx',
}
crt:mutex(crt:option('-f --from'), crt:argument('host'):args('?'))
crt:mutex(crt:option('-f --from'), crt:option('-i --ip'))
crt:mutex(crt:option('-f --from'), crt:option('-p --port'))
crt:flag('-v --verbose')

-- SPF checker
local spf = parser:command 'spf' {
  description = 'check spf for given sender [ip]',
  epilog = 'for more info see https://github.com/hertogp/nx',
}
spf:argument 'sender@domain.tld'
spf:option '-i --ip'

--[[-- cmd TODO: --]]
-- * rpki
-- * dane
-- * caa
-- * mx
-- * tlsa
-- * whois
-- ------- combinators
-- * domain (combines other commands)

--[[-- dispatch --]]

local args = parser:parse()
assert(args.command, 'nx cmd [opts], cmd is mandatory')
local cmd = require(sf('cmd.%s', args.command))
cmd.main(args)
