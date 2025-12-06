--[[--- DNS.RR ---]]
local dump = require 'dump'
local sf = string.format
local byte = string.byte
local sub = string.sub
local unpack = string.unpack

print('DNS.RR ------------------------------------------------')

--[[--- helpers ---]]

local function addrev(t, f)
  -- it's not safe to add `table` keys while traversing `table`
  local copy = {}
  for k, v in pairs(t) do
    copy[k] = v
  end
  for k, v in pairs(copy) do
    t[v] = k
  end
end

--[[--- parse helpers ---]]

-- these parsers parse not the entire wire-form of a packet, but rather
-- the inidividual RRDATA binaries in `qres` as returned by unbound:resolve()

local parse = {}

function parse.charstr(bin, offset) return unpack('s1', bin, offset) end

function parse.domainname(bin, offset)
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3`
  offset = offset or 1
  local label, labels = '', {}
  repeat
    label, offset = parse.charstr(bin, offset)
    labels[#labels + 1] = #label > 0 and label or nil
  until #label == 0
  return table.concat(labels, '.') .. '.', offset
end

function parse.ipv4(bin, offset)
  offset = offset or 1
  return sf('%d.%d.%d.%d', unpack('BBBB', bin, offset)), offset + 4
end

--[[--- TYPES ---]]

local TYPES = {
  A = 1,
  AAAA = 28,
  CAA = 257,
  CNAME = 5,
  DNAME = 39,
  DS = 43,
  MX = 15,
  NS = 2,
  PTR = 12,
  SOA = 6,
  TXT = 16,
}
-- add reverse mapping
addrev(TYPES)

-- TYPES helper functions
function TYPES.tostring(self, key)
  local s = string.upper(key)
  return rawget(self, s) and s or rawget(self, tonumber(key))
end

function TYPES.tonumber(self, key)
  local n = tonumber(key)
  return rawget(self, n) and n or rawget(self, string.upper(key))
end

setmetatable(TYPES, {
  -- cater for wrong case and/or number as string
  __index = function(t, key) return rawget(t, tonumber(key)) or rawget(t, string.upper(key)) end,
})

--[[--- RR ---]]
--  +------DNS message ---+
--  |        Header       |
--  +---------------------+
--  /       Question      / the question(s) for the name server
--  +---------------------+
--  /        Answer       / RRs answering the question
--  +---------------------+
--  /      Authority      / RRs pointing toward an authority
--  +---------------------+
--  /      Additional     / RRs holding additional information
--  +---------------------+
---
--- and query reply:
---
--   0  1  2  3  4  5  6  7  8  9  0 11 12 13 14 15
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- /                      NAME                     / length encoded owner domain name
-- /                                               /
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                      TYPE                     | unsigned 16 bit integer
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                     CLASS                     | unsigned 16 bit integer
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                      TTL                      | unsigned 32 bit integer in 0..2**31 -1
-- |                                               |
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- |                     RDLEN                     | unsigned 16 bit integer, the length or RDATA
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
-- /                     RDATA                     / variable length binary
-- /                                               /
-- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

--- RR maps NAME -> {decode, encode} for lunbound query results
-- qresult is table with:
-- * sequence of individual RR's, and
-- * named fields (unfortunately field ttl is missing)
--   - havedata (boolean), n <num> of RR's in index qres[1..n]
--   - nxdomain (boolean), qclass (num) qname (str) , qtype (num), rcode (num)
--   - secure (boolean)
--   we add:
--   - rtype (str for qtype), rdata {} (decoded RDATA entries)
--   nb: `qres[x]` = raw binary, `qres.rdata[x]` = decoded to a map `{field_name=value}`
local RR = {}

--- rdata = { ip = str }
RR.A = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1`
  decode = function(qres)
    qres.rdata = { ip = sf('%d.%d.%d.%d', unpack('BBBB', qres[1])) }
    return qres
  end,
}

--- rdata = { ip = str }
RR.AAAA = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1`
  decode = function(qres)
    qres.rdata = { raw = qres[1] }
    return qres
  end,
}

--- rdata = { flags = num, tag = str, val = str }
RR.CAA = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc8659#name-syntax`
  decode = function(qres)
    qres.rdata = {}
    for i, raw in ipairs(qres) do
      local flags, tag, val = unpack('Bs1z', raw .. '\0')
      qres.rdata[i] = {
        flags = flags,
        tag = tag,
        val = val,
      }
    end
    return qres
  end,
}

RR.DNAME = {
  -- `:Open `
  -- dig dname.dns.netmeister.org
  decode = function(qres)
    qres.rdata = { raw = qres[1] }
    return qres
  end,
}

RR.DS = {
  -- `:Open `
  decode = function(qres)
    qres.rdata = { raw = qres[1] }
    return qres
  end,
}

--- rdata = { {pref = num, name = str}, .. }
RR.MX = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9`
  decode = function(qres)
    qres.rdata = {}
    for i, raw in ipairs(qres) do
      local pref, offset = unpack('>I2', raw)
      qres.rdata[i] = {
        pref = pref,
        name = parse.domainname(raw, offset),
      }
    end
    return qres
  end,
}

--- rdata = { str, str, .. }
RR.NS = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11`
  decode = function(qres)
    qres.rdata = {}
    for i, raw in ipairs(qres) do
      qres.rdata[i] = parse.domainname(raw, 1)
    end
    return qres
  end,
}

--- rdata = { str }
RR.PTR = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12`
  decode = function(qres)
    qres.rdata = parse.domainname(qres[1])
    return qres
  end,
}

--- rdata = { mname(str), rname(str), serial(num), refresh(num), retry(num), expire(num) }
RR.SOA = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13`
  decode = function(qres)
    local bin = qres[1]
    local offset, mname, rname, serial, refresh, retry, expire
    mname, offset = parse.domainname(bin, 1)
    rname, offset = parse.domainname(bin, offset)
    serial, refresh, retry, expire = unpack('>I4I4I4I4', bin, offset)

    qres.rdata = {
      mname = mname,
      rname = rname,
      serial = serial,
      refresh = refresh,
      retry = retry,
      expire = expire,
    }
    return qres
  end,
}

--- rdata = { (str), .. }
RR.TXT = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14`
  decode = function(qres)
    qres.name = TYPES[qres.qtype]
    qres.rdata = {}
    for i, bin in ipairs(qres) do
      qres.rdata[i] = parse.charstr(bin, 1)
    end
    return qres
  end,
}

--[[--- decode ---]]

local M = {
  TYPES = TYPES,
}

function M.decode(qres)
  local rtype = TYPES:tostring(qres.qtype)
  local codec = RR[rtype]
  if codec then
    qres.rtype = rtype
    return codec.decode(qres)
  end
  return nil, sf('no codec for %s (%s)', qres.qtype, rtype or '?')
end

return M
