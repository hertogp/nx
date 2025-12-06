--[[--- DNS.rr ---]]
-- local dump = require 'dump'
local b64 = require 'base64'

local sf = string.format
local sub = string.sub
local unpack = string.unpack

--[[--- helpers ---]]

local function addrev(t)
  -- it's not safe to add `table` keys while traversing `table`
  local copy = {}
  for k, v in pairs(t) do
    copy[k] = v
  end
  for k, v in pairs(copy) do
    t[v] = k
  end
end

local char2hex = {}
for c = 0, 255 do
  char2hex[string.char(c)] = sf('%02X', c)
end

local function tohex(s) return (string.gsub(s, '.', char2hex)) end
--[[--- parsers ---]]

-- these parsers parse not the entire wire-form of a packet, but rather
-- the inidividual rrDATA binaries in `qres` as returned by unbound:resolve()

local parse = {}

function parse.charstr(bin, offset)
  -- <len-octect><len x octect ..>
  offset = offset or 1
  return unpack('s1', bin, offset)
end

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
function parse.ipv6(bin, offset)
  offset = offset or 1
  return sf('%x:%x:%x:%x:%x:%x:%x:%x', unpack('>I2I2I2I2I2I2I2I2', bin, offset)), offset + 8
end

--[[--- TYPES ---]]

local TYPES = {
  A = 1,
  AAAA = 28,
  CAA = 257,
  CNAME = 5,
  DNAME = 39,
  DNSKEY = 48,
  DS = 43,
  MX = 15,
  NS = 2,
  NSEC3PARAM = 51,
  PTR = 12,
  RRSIG = 46,
  SOA = 6,
  TXT = 16,
}
-- add reverse mapping
addrev(TYPES)

setmetatable(TYPES, {
  -- cater for wrong case and/or number as string
  __index = function(t, key) return rawget(t, tonumber(key)) or rawget(t, string.upper(key)) end,
})

-- TYPES helper functions
function TYPES.tostring(self, key)
  local s = string.upper(key)
  return rawget(self, s) and s or rawget(self, tonumber(key))
end

function TYPES.tonumber(self, key)
  if nil == key then return nil end
  local n = tonumber(key)
  return rawget(self, n) and n or rawget(self, string.upper(key))
end

--[[--- rr ---]]
---
--- An RR has the following format:
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
--
-- unbound:resolve(..) returns:
-- {
--    [1] = "&\3\16 \2\1\0\15\0\0\0\0\0\0\4�",
--    [2] = ..
--    havedata = true,
--    n = 1,
--    nxdomain = false,
--    qclass = 1,
--    qname = "rws.nl",
--    qtype = 28,
--    rcode = 0,
--    secure = true,
--
--    -- rr.decode added
--    rdata = {
--        [1] = "2603:1020:201:f:0:0:0:4a0",
--        [2] = "..",
--    },
--    rtype = "AAAA",
-- }
--

-- unbound:resolve(name, qtype) -> qres with:
-- - qname, qtype, qclass
-- - havedata (true/false), n = num of entries qres[1]..[n]
-- - nxdomain (true/false), secure (true/false)
--
-- rr.NAME.decode(qres) -> adds:
-- - rname (str) = name of qtype
-- - rdata ({..}) = list of translated RR-entries in qres or map

--- `rr.NAME` -> {`decode(qres)`, `encode(qres)`}
--- where `qres` is a lunbound query result:
-- * `qres[1..n]` = `{bin_1, .. , bin_n}`
-- * `havedata` (boolean), n <num> of rr's in qres' sequence
-- * `nxdomain` (boolean),
-- * `qclass` (num)
-- * `qname` (str) ,
-- * `qtype` (num),
-- * `rcode` (num)
-- * `secure` (boolean)
-- decoding adds:
-- + `rtype` (str for qtype), rdata {} (decoded RDATA entries)
-- + `rdata[1..n]` = { data_1, .., data_n }
-- where
-- * bin_x is the raw binary string of the RR, and
-- * data_x is either a string for simple values *or* a table with k,v-pairs
local rr = {}

--- Sets `qres.rdata` = { (str), .. }
rr.A = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1`
  decode = function(qres)
    qres.rdata = {}
    for i, bin in ipairs(qres) do
      qres.rdata[i] = parse.ipv4(bin)
    end
    return qres
  end,
}

--- Sets `qres.rdata` = { (str), .. }
rr.AAAA = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc3596#section-2.2`
  decode = function(qres)
    qres.rdata = {}
    for i, bin in ipairs(qres) do
      qres.rdata[i] = parse.ipv6(bin)
    end
    return qres
  end,
}

--- Sets `qres.rdata` = { flags(num), tag(str), val(str) }
rr.CAA = {
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

--- Sets `qres.rdata` = { (str) }
rr.DNAME = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc6672.html#section-2.1`
  -- dig dname.dns.netmeister.org
  decode = function(qres)
    local dname = parse.domainname(qres[1])
    qres.rdata = { dname }
    return qres
  end,
}

local _keytype = {
  [256] = 'ZSK',
  [257] = 'KSK',
}
local _alg = {
  -- TODO: generate module with numbers by download dns-sec-alg-numbers
  -- `:Open https://www.rfc-editor.org/rfc/rfc4034#appendix-A.1`
  -- `:Open https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml`
  [0] = 'reserved',
  [1] = 'RSAMD5',
  [2] = 'DH',
  [3] = 'DSA',
  [4] = 'ECC',
  [5] = 'RSASHA1',
  [6] = 'DSA-NSEC3-SHA1',
  [7] = 'RSASHA1-NSEC3-SHA1',
  [8] = 'RSASHA256',
  [9] = 'reserved',
  [10] = 'RSASHA512',
  [11] = 'reserved',
  [12] = 'ECC-GOST',
  [13] = 'ECDSAP256SHA256',
  [14] = 'ECDSAP384SHA384',
  [15] = 'ED25519',
  [16] = 'ED448',
  [17] = 'SM2SM3',
  [23] = 'ECC-GOST12',
  [252] = 'INDIRECT',
  [253] = 'PRIVATEDNS',
  [254] = 'PRIVATEOID',
  [255] = 'reserved',
}

local function _calc_keytag(bin, algo)
  -- test with dig example.com. DNSKEY +dnssec +multi @9.9.9.9
  if 1 == algo then
    local acc = unpack('>I3', bin, #bin - 2)
    return acc >> 8
  else
    local acc, offset, bb = 0, 1, 0
    repeat
      bb, offset = unpack('>I2', bin, offset)
      acc = acc + bb
      print('bb', acc, bb, offset, #bin)
    until #bin <= offset
    acc = acc + (acc >> 16)
    return acc & 0xffff
  end
end
--- Sets `qres.rdata` = { (str), .. }
rr.DNSKEY = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc4034#section-2`
  -- `:Open https://www.rfc-editor.org/rfc/rfc4034#appendix-B` -- TODO: for keytag
  decode = function(qres)
    qres.rdata = {}
    for i, bin in ipairs(qres) do
      local flags, proto, algo, offset = unpack('>I2BB', bin)
      local pubkey = sub(bin, offset)
      local keytype = _keytype[flags] or 'other'
      qres.rdata[i] = {
        flags = flags,
        proto = proto,
        algo = algo,
        pubkey = b64.encode(pubkey),
        _keytype = keytype,
        _keyid = _calc_keytag(bin, algo),
        _alg = _alg[algo] or 'unknown',
      }
    end
    return qres
  end,
}

-- Sets `qres.rdata` = { keytag(num), algo(num), dtype(num), digest(str) }
rr.DS = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc4034#section-5`
  decode = function(qres)
    if false == qres.havedata then return nil, 'no data' end
    local keytag, algo, dtype, offset = unpack('>I2BB', qres[1])
    local digest = sub(qres[1], offset)
    digest = tohex(digest)
    qres.rdata = { keytag = keytag, algo = algo, dtype = dtype, digest = digest }
    return qres
  end,
}

--- rdata = { {pref = num, name = str}, .. }
rr.MX = {
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

--- Sets `qres.rdata` = { (str), .. }
rr.NS = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11`
  decode = function(qres)
    qres.rdata = {}
    for i, raw in ipairs(qres) do
      qres.rdata[i] = parse.domainname(raw, 1)
    end
    return qres
  end,
}

--- Sets `qres.rdata` = { (str), .. }
rr.PTR = {
  -- `:Open https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12`
  decode = function(qres)
    qres.rdata = {}
    for i, bin in ipairs(qres) do
      qres.rdata[i] = parse.domainname(bin)
    end
    return qres
  end,
}

--- Sets `qres.rdata` = {}
rr.RRSIG = {
  -- `:Open  https://www.rfc-editor.org/rfc/rfc4034#section-3`
  decode = function(qres)
    qres.rdata = {}
    for i, bin in ipairs(qres) do
      local name, signature
      local type, algo, labels, ttl, notafter, notbefore, keytag, offset = unpack('>I2BBI4I4I4I2', bin)
      name, offset = parse.domainname(bin, offset)
      signature = unpack('z', bin .. '\0', offset)
      print(tohex(signature))
      qres.rdata[i] = {
        type = type,
        tname = TYPES:tostring(type),
        algo = algo,
        labels = labels,
        ttl = ttl,
        notafter = os.date('!%Y%m%d%H%M%S', notafter),
        notbefore = os.date('!%Y%m%d%H%M%S', notbefore),
        keytag = keytag,
        name = name,
        signature = b64.encode(signature),
      }
    end
    return qres
  end,
}
--- Sets `qres.rdata` = { mname(str), rname(str), serial(num), refresh(num), retry(num), expire(num) }
rr.SOA = {
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
rr.TXT = {
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
  if nil == qres then return nil, 'no query result' end
  local rtype = TYPES:tostring(qres.qtype)
  local codec = rr[rtype]
  if codec then
    qres.rtype = rtype
    return codec.decode(qres)
  end
  return nil, sf('no codec for %s (%s)', qres.qtype, rtype or '?')
end

return M
