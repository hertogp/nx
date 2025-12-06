--[[--- lunbound ---]]
local sf = string.format
local dump = require 'dump'
local ub = require('lunbound').new({
  async = false,
  trusted = '. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237 C7F8EC8D',
})

-- trusted <- dig . DS +dnssec
local rr = require 'lib.dns.rr'

local M = {}

function M.lookup(name, qtype)
  local rrtype = rr.TYPES:tonumber(qtype)
  print(qtype, rrtype)
  if nil == rrtype then return nil, sf('%s unknown dns record type', qtype) end
  local qres = ub:resolve(name, rrtype)
  print('qres', dump(qres))
  return rr.decode(qres)
end

return M
