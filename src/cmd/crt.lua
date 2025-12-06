-- `:Open https://github.com/lunarmodules/luasec/wiki/LuaSec-1.3.x`
-- `:Open https://daurnimator.github.io/lua-http/0.4/#connection:checktls`
-- `:Open https://lunarmodules.github.io/luasocket/tcp.html`
-- `:Open https://25thandclement.com/~william/projects/luaossl.pdf` -- X509

local sock = require('socket') -- `:Open https://github.com/lunarmodules/luasocket`
local ssl = require('ssl') -- `:Open https://github.com/lunarmodules/luasec`
local x509 = require('openssl.x509') -- `:Open https://25thandclement.com/~william/projects/luaossl.pdf` -- X509
local dump = require 'dump'
local cq = {
  dns = require 'cqueues.dns',
  pkt = require 'cqueues.dns.packet',
}

--[[ HELPERS ]]

local sf = string.format

--- Returns a table with .ip4 and .ip6 list of IP's for given name
---@param host string
---@param address string
---@return table ipv4v6
local function resolve(host, address)
  if nil == host then return {} end
  local rv = { address }

  local pkt = cq.dns.query(host, 'A')
  if pkt then
    for addr, _ in pkt:grep({ section = 'ANSWER' }) do
      local ip = sf('%s', addr)
      rv[#rv + 1] = ip
    end
  end

  pkt = cq.dns.query(host, 'AAAA')
  if pkt then
    for addr, _ in pkt:grep({ section = 'ANSWER' }) do
      local ip = sf('%s', addr)
      rv[#rv + 1] = ip
    end
  end
  if #rv == 0 then print(sf('resolve %s, no ip addresses found', host)) end

  return rv
end

--- Returns table with cert chain information
--- @param host string
--- @param ip string
--- @param port number
--- @return table crt
local function getcrt(host, ip, port)
  local crt = {
    host = host,
    ip = ip or host,
    port = port or 443,
  }

  local params = { -- `:Open https://github.com/lunarmodules/luasec/wiki/LuaSec-1.3.x#sslnewcontextparams`
    -- * ssl.newcontext for params
    mode = 'client', -- {client, server}
    protocol = 'any', -- {any, tlsv1, tlsv1_{1,2,3}}
    options = 'all', -- doesn't seem to be necessary
    depth = 5, --      seems to have no effect, get full chain regardless
    capath = '/etc/ssl/certs',
  }

  -- 1. open tcp connection -> TCP client object
  crt.chain = {}
  local chain = {} -- here so we can skip
  local succ, msg -- dito, succ must be nil/false here!
  local conn = sock.tcp() --> TCP master object

  conn:settimeout(2, 'b') -- timeout in seconds
  local ok, err = conn:connect(crt.ip, crt.port) --> TCP client object (via :connect)
  if not ok then
    crt.status = sf('[tcp connect] %s', err)
    goto skip
  end

  crt.remote_ip, crt.remote_port, crt.inetfam = conn:getpeername()
  crt.remote_ip = sf('%s', crt.remote_ip) -- userdata -> string

  -- 2. upgrade to SSL connection -> userdata
  conn = ssl.wrap(conn, params)
  conn:sni(crt.host)
  while not succ do
    -- `:Open https://github.com/lunarmodules/luasec/wiki/LuaSec-1.3.x#conndohandshake`
    succ, msg = conn:dohandshake()
    if 'wantread' == msg then
      sock.select({ conn }, nil)
    elseif 'wantwrite' == msg then
      sock.select(nil, { conn })
    elseif not succ then
      print('error', msg)
      crt.status = sf('[ssl handshake] %s', msg)
      -- conn:close()
      break
    end
  end
  if crt.status then goto skip end

  -- ok, handshake succeeded so get the info
  crt.rx, crt.tx, crt.age = conn:getstats()
  crt.sni = conn:getsniname()
  crt.peerverified = conn:getpeerverification()
  crt.alpn = conn:getalpn() -- always nil ?

  -- 3. get CERTIFICATE CHAIN
  -- `:Open https://github.com/lunarmodules/luasec/wiki/LuaSec-1.3.x#conn_getpeerchain`

  chain = conn:getpeerchain() or {} -- sequence of X509 certificates (userdata)
  -- conn:close()
  for k, v in ipairs(chain) do
    -- `:Open https://25thandclement.com/~william/projects/luaossl.pdf`
    local x = x509.new(v:pem())

    -- x509.new(v:pem()):getExtension[k] are richer than cert:extensions()
    local exts = {}
    for idx = 1, x:getExtensionCount() do
      local ext = x:getExtension(idx)
      exts[#exts + 1] = {
        critical = ext:getCritical(),
        id = ext:getID(),
        shortname = ext:getShortName(),
        longname = ext:getLongName(),
        getname = ext:getName(),
        text = ext:text(),
      }
    end

    local issuer = {}
    for _, field in ipairs(v:issuer()) do
      -- issuer {commonName=, countryName=, organizationName=, organizationalUnitName=}
      issuer[field.name] = field.value
    end

    local subject = {}
    for _, subj in ipairs(v:subject()) do
      --subject {commonName=, countryName=, organizationName=, stateOrProvinceName=}
      subject[subj.name] = subj.value
    end

    local altnames = v:extensions()['2.5.29.17'] or {}
    for _, dnsname in ipairs(altnames.dNSName or {}) do
      altnames[#altnames + 1] = dnsname
    end

    local notbefore, notafter, lifespan = x:getLifetime() -- (epoch) seconds
    crt.chain[k] = {
      pubkey = v:pubkey(), -- looong text
      pem = v:pem(), -- even looonger text
      valid = v:validat(os.time()), -- notbefore <= now() <= notafter
      serial = v:serial(),
      digest = v:digest(),
      notbefore = os.date('%Y-%m-%d', notbefore),
      notafter = os.date('%Y-%m-%d', notafter),
      lifespan = math.floor(lifespan / 24 / 3600),
      ttl = math.floor((notafter - os.time()) / 24 / 3600),
      signature = v:getsignaturename(),
      extensions = v:extensions(),
      altnames = altnames,
      issuer = issuer,
      subject = subject,
      exts = exts,
    }
  end
  ::skip::
  conn:close()

  --[[-- OPENSSL --]]

  return crt
end

local function prncrt(crt, verbose)
  if verbose then
    print(dump(crt))
  else
    print('ssh')
  end
end

local function mktodos(args)
  local todo = {}
  if args.from then
    local fh = io.open(args.from, 'r')
    assert(fh, sf('[crt][error] - could not read %s', args.from))
    for line in fh:lines() do
      if line:match('^%s*#') then goto skip end
      local host = line:match('^%S+')
      if host then
        todo[#todo + 1] = {
          host = host,
          port = line:match('p=(%S+)') or args.port or 443,
          addr = line:match('ip=(%S+)') or args.ip,
        }
      end
      ::skip::
    end
    fh:close()
  else
    todo = { { host = args.host, port = args.port, ip = args.ip } }
  end

  local rv = {}
  for _, v in ipairs(todo) do
    for _, ip in ipairs(resolve(v.host, v.ip)) do
      rv[#rv + 1] = {
        host = v.host,
        port = v.port,
        ip = ip,
      }
    end
  end

  return rv
end
--[[-- MAIN --]]
--TODO: handle errors, e.g. for microsoft.com

local function main(args)
  local todos = mktodos(args)
  for _, todo in ipairs(todos) do
    local crt = getcrt(todo.host, todo.ip, todo.port)
    local prefix = sf('%s;%s;%s', crt.host, crt.remote_ip or crt.ip, crt.port)
    local len = #crt.chain
    local ok = crt.peerverified and 'ok' or 'nok'
    if crt.status then
      print(prefix, crt.status)
    else
      for idx, c in ipairs(crt.chain) do
        ok = idx == 1 and ok or ''
        local alt = table.concat(c.altnames, ',')
        local subj = c.subject.commonName
        local issr = c.issuer.commonName
        print(
          sf('%-50s [%2s/%-2s] %5s %s %3s  %25s <- %s  %s', prefix, idx, len, c.ttl, c.notafter, ok, subj, issr, alt)
        )
      end
    end
  end
end

return { main = main }
