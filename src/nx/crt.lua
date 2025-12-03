-- `:Open https://github.com/lunarmodules/luasec/wiki/LuaSec-1.3.x`
-- `:Open https://daurnimator.github.io/lua-http/0.4/#connection:checktls`
-- `:Open https://lunarmodules.github.io/luasocket/tcp.html`

local sock = require('socket') -- `:Open https://github.com/lunarmodules/luasocket`
local ssl = require('ssl') -- `:Open https://github.com/lunarmodules/luasec`
local x509 = require('openssl.x509')
local dump = require 'dump'
local cq = {
  dns = require 'cqueues.dns',
  pkt = require 'cqueues.dns.packet',
}

--[[ HELPERS ]]

local sf = string.format

--- Returns a table with .ip4 and .ip6 list of IP's for given name
local function getips(name)
  if nil == name then return {} end
  local rv = { ip = {}, ip4 = {}, ip6 = {} }

  local pkt = cq.dns.query(name, 'A')
  if pkt then
    for ip, _ in pkt:grep({ section = 'ANSWER' }) do
      local addr = sf('%s', ip)
      rv.ip4[#rv.ip4 + 1] = addr
      rv.ip[#rv.ip + 1] = addr
    end
  end

  pkt = cq.dns.query(name, 'AAAA')
  if pkt then
    for ip, _ in pkt:grep({ section = 'ANSWER' }) do
      local addr = sf('%s', ip)
      rv.ip6[#rv.ip6 + 1] = addr
      rv.ip[#rv.ip + 1] = addr
    end
  end
  return rv
end

--- Returns table with cert chain information
--- @param name string
--- @param ip string
--- @param port number
--- @return table crt
local function getcrt(name, ip, port)
  local crt = {
    hostname = name,
    ip = ip or name,
    port = port or 443,
  }

  local params = { -- * ssl.newcontext for params
    mode = 'client', -- {client, server}
    protocol = 'any', -- {any, tlsv1, tlsv1_{1,2,3}}
    options = 'all', -- doesn't seem to be necessary
    depth = 5, --      seems to have no effect, get full chain regardless
  }

  -- TCP client object
  local tcpc = sock.tcp() --> TCP master object
  tcpc:connect(crt.ip, crt.port) --> TCP client object (via :connect)
  crt.remote_ip, crt.remote_port, crt.inetfam = tcpc:getpeername()

  -- SSL connection (userdata)
  local sslc = ssl.wrap(tcpc, params)
  sslc:sni(crt.hostname)
  crt.handshake = sslc:dohandshake()
  crt.rx, crt.tx, crt.age = sslc:getstats()
  crt.sni = sslc:getsniname()
  crt.peerverified = sslc:getpeerverification()
  crt.alpn = sslc:getalpn() -- nil ?

  -- CERTIFICATE CHAIN
  -- `:Open https://github.com/lunarmodules/luasec/wiki/LuaSec-1.3.x#conn_getpeerchain`
  local chain = sslc:getpeerchain() or {} -- sequence of X509 certificates (userdata)

  crt.chain = {}
  for k, v in ipairs(chain) do
    local x = x509.new(v:pem())
    local notbefore, notafter, lifespan = x:getLifetime() -- used later on

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
      issuer[field.name] = field.value
    end

    local subject = {}
    for _, subj in ipairs(v:subject()) do
      subject[subj.name] = subj.value
    end

    local altnames = v:extensions()['2.5.29.17'] or {}
    for _, dnsname in ipairs(altnames.dNSName or {}) do
      altnames[#altnames + 1] = dnsname
    end

    crt.chain[k] = {
      pubkey = v:pubkey(),
      pem = v:pem(),
      valid = v:validat(os.time()),
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

  -- send/receive some stuff
  -- `:Open https://www.notebook.kulchenko.com/programming/https-ssl-calls-with-lua-and-luasec`
  -- print('sslc:send', sslc:send('GET / HTTP/1.1\n\n'))
  -- local line, err = sslc:receive()
  -- print('err', err)
  -- print('line', line)
  -- print('sslc:close', sslc:close(), '<--')

  --[[-- OPENSSL --]]
  -- `:Open https://25thandclement.com/~william/projects/luaossl.pdf`

  local cert = chain[1] --<-- simply chain[1] !
  local c = x509.new(cert:pem())
  crt.version = c:getVersion()
  local before, after, span = c:getLifetime()
  crt.notbefore = os.date('%Y-%m-%d', before)
  crt.notafter = os.date('%Y-%m-%d', after)
  crt.lifespan = math.floor(span / 24 / 3600) -- in days
  crt.ttl = math.floor((after - os.time()) / 24 / 3600)
  crt.altnames = crt.chain[1].altnames.dNSName
  return crt
end

local function prncrt(crt, verbose)
  if verbose then
    print(dump(crt))
  else
    print('ssh')
  end
end

--[[-- MAIN --]]
--TODO: handle errors, e.g. for microsoft.com

local function main(args)
  local todo = {}
  if args.from then
    local fh = io.open(args.from, 'r')
    assert(fh, sf('could not read %s', args.from))
    for line in fh:lines() do
      todo[#todo + 1] = {
        host = line:match('^%S+'),
        port = line:match('p=(%S+)'),
        ip = line:match('ip=(%S+)'),
      }
    end
  else
    todo = { { host = args.domain, ip = args.ip, port = args.port } }
  end

  for _, itm in ipairs(todo) do
    local ips = getips(itm.host)
    local chain = {}
    for _, ip in ipairs(ips.ip) do
      chain[#chain + 1] = getcrt(itm.host, ip, itm.port)
    end
    chain.ips = ips.ip

    for _, crt in ipairs(chain) do
      -- prncrt(crt, args.verbose)
      print(
        crt.hostname,
        sf('%20s', crt.ip),
        crt.port,
        crt.ttl,
        crt.notbefore,
        crt.notafter,
        table.concat(crt.altnames, ',')
      )
    end
  end
end

return { main = main }
