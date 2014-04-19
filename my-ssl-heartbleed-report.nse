-- based on http://thesprawl.org/research/writing-nse-scripts-for-vulnerability-scanning/

local stdnse = require "stdnse"
local vulns = require "vulns"

local FID

prerule = function()
  FID = vulns.save_reports()
  if FID then
    return true
  end
  return false
end

postrule = function()
  if nmap.registry[SCRIPT_NAME] then
    FID = nmap.registry[SCRIPT_NAME].FID
    if vulns.get_ids(FID) then
      return true
    end
  end
  return false
end

prerule_action = function()
  nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
  nmap.registry[SCRIPT_NAME].FID = FID
  return nil
end

postrule_action = function()
  local filter = {state = vulns.STATE.VULN}
  local list = vulns.find(FID, filter)
  if list then
    local out = {}
    for _, vuln_table in ipairs(list) do
      local ip = vuln_table.host.ip
      local port = vuln_table.port.number
      local state = vulns.STATE_MSG[vuln_table.state]
      local title = vuln_table.title
      table.insert(out, string.format("%s:%d;%s;%s", ip, port, title, state))

    end
    return stdnse.format_output(true, out)
  end
end

local tactions = {
  prerule = prerule_action,
  postrule = postrule_action,
}

action = function(...) return tactions[SCRIPT_TYPE](...) end

-- vim: set ft=lua ts=2 sw=2 et ai sm:
