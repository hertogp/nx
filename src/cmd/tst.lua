--[[--- TST ---]]
local utils = require 'lib.utils'
local rr = require 'lib.dns.rr'
local dump = require 'dump'
local sf = string.format

print('rr', rr)
print('utils', utils)
--[[--- main ---]]

local M = {}

function M.main(args)
  local res, msg
  print(dump(args))
  local rrtype = args.rrtype
  local qtype = rr.TYPES:tonumber(args.rrtype)
  if not qtype then print(sf('%s unknown, default to A', args.rrtype)) end

  res = utils.lookup(args.name, rr.TYPES:tonumber(rrtype))
  res, msg = rr.decode(res)
  if res then
    print('ok', dump(res))
  else
    print('msg', msg)
  end
end

return M
