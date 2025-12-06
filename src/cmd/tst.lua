--[[--- TST ---]]
local dns = require 'lib.dns'
local dump = require 'dump'
local sf = string.format

--[[--- main ---]]

local M = {}

function M.main(args)
  local res, msg

  res, msg = dns.lookup(args.name, args.rrtype or 'A')
  if res then
    print('<ok>', dump(res))
  else
    print('<error>', msg)
  end
end

return M
