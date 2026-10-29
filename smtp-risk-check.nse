local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to use EHLO and HELP to gather the Extended commands supported by an
SMTP server, then flags two security-relevant findings:
  - User enumeration risk if VRFY or EXPN are supported
  - Unencrypted mail risk if STARTTLS is not advertised
]]

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service({ 25, 465, 587 },
  { "smtp", "smtps", "submission" })

function go(host, port)
  local options = {
    timeout = 10000,
    recv_before = true,
    ssl = true,
  }

  local domain = stdnse.get_script_args('smtp-commands.domain') or
  smtp.get_domain(host)

  local result, status = {}
  -- Try to connect to server.
  local socket, response = smtp.connect(host, port, options)
  if not socket then
    return false, string.format("Couldn't establish connection on port %i",
      port.number)
  end

  status, response = smtp.ehlo(socket, domain)
  if not status then
    return status, response
  end

  response = response:gsub("\r", "")
                     :gsub("^%s*(.-)%s*$", "%1")
                     :gsub("%f[^\0\n]250[-%s]+", "")
                     :gsub("\n", ", ")
                     :gsub("%s+", " ")
  table.insert(result, response)

  status, response = smtp.help(socket)
  if status then
    response = response:gsub("\r", "")
                       :gsub("^%s*(.-)%s*$", "%1")
                       :gsub("%f[^\0\n]214[-%s]+", "")
                       :gsub("%s+", " ")
    table.insert(result, response)
    smtp.quit(socket)
  end

  return true, result
end

-- Helper: search the combined EHLO/HELP text for risky commands
local function check_risks(combined_text)
  local findings = {}
  local upper_text = combined_text:upper()

  local risky = {}
  if upper_text:find("VRFY") then
    table.insert(risky, "VRFY")
  end
  if upper_text:find("EXPN") then
    table.insert(risky, "EXPN")
  end
  if #risky > 0 then
    table.insert(findings, "[!] User enumeration possible via " .. table.concat(risky, "/"))
  end

  if not upper_text:find("STARTTLS") then
    table.insert(findings, "[!] STARTTLS not advertised -- mail may be sent/received unencrypted")
  end

  return findings
end

action = function(host, port)
  local status, result = go(host, port)

  if not status then
    return result
  else
    if #result > 0 then
      local final = {}
      for index, test in ipairs(result) do
        table.insert(final, test)
      end

      -- combine EHLO + HELP text into one string to scan for risky keywords
      local combined = table.concat(final, " ")
      local findings = check_risks(combined)

      for _, f in ipairs(findings) do
        table.insert(final, f)
      end

      return table.concat(final, "\n ")
    end
  end
end