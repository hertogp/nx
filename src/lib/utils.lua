-- using lunbound
local ub = require('lunbound').new({
  async = false,
  trusted = '. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237 C7F8EC8D',
})
print('ub', ub)
local rr = require 'lib.dns.rr'
local dump = require 'dump'

local M = {}

function M.lookup(name, rrtype)
  rrtype = rr.TYPES:tonumber(rrtype)
  local res = ub:resolve(name, rrtype)

  print('ub.fd', ub.fd)
  print('ub.resolve', ub.resolve)
  print('ub.resolve_async', ub.resolve_async)
  print('ub.process', ub.process)
  print('ub.wait', ub.wait)
  print('ub.poll', ub.poll)
  print('ub.getfd', ub.getfd)

  local cb = function(rv)
    print('cb', type(rv), rv)
    for k, v in pairs(rv) do
      print('cb', k, v)
    end
  end
  print('async', ub:resolve_async(cb, name, rrtype))
  -- print('process', ub:process())
  print('wait', ub:wait())
  local fd = ub:getfd()
  print('fd', fd, type(fd))

  return res
end

return M
