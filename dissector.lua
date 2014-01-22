--hack lpath/cpath to have m3da libs loadable...
package.cpath=package.cpath..";./m3da/?.so"
package.path=package.path..";./m3da/?.lua"

local bysant = require'bysant'
local niltoken = require 'niltoken'

require 'print' --TODO DEBUG to remove

-- create M3DA protocol and its fields
local m3da_proto = Proto ("m3da","Micro M2M Data Access Protocol")
local f_id = ProtoField.string("id", "Peer Identifier")
local f_mac = ProtoField.string("mac", "Message Authentication Code")
local f_payload = ProtoField.string("payload", "Payload data")
local f_status = ProtoField.string("status", "Transaction status")
local f_challenge = ProtoField.string("challenge", "Challenge request")
local f_nonce = ProtoField.string("nonce", "Next nonce")
local f_ticketid = ProtoField.string("ticketid", "Ticket ID")
local f_path = ProtoField.string("path", "Path")


m3da_proto.fields = {f_id, f_payload, f_mac, f_status, f_challenge, f_nonce, f_ticketid, f_path}

local function stringtohex(s)
    return s:gsub("(.)", function (c) return string.format("%02X",string.byte(c)) end)
end

local function exist(n)
    if n == nil or niltoken(n) == nil then return false else return true end
end


local function parse_message(tvb, tree, data, metrics)
    tree = tree:add(tvb(metrics.offset, metrics.length), "Message")
    tree:add(f_path, tvb(metrics.path.offset, metrics.path.length), data.path)
    tree:add(f_ticketid, tvb(metrics.ticketid.offset, metrics.ticketid.length), data.ticketid)
    for k, v in pairs(data.body) do
        if type(v) == 'table' then
            local t
            if not v.__class then
                t = "LIST"
            else
                if v.__class == "QuasiPeriodicVector" then
                    t = string.format("QPV start=%f, period=%f, n=%d", v.start, v.period, #v.shifts)
                    local Y = {v.start}
                    local i = 1
                    while #v.shifts > 1 do
                        local n, s = table.remove(v.shifts), table.remove(v.shifts)
                        for j=i+1, i+n do Y[j] = Y[j-1] + v.period end
                        i = i+n+1
                        Y[i] = Y[i-1]+s
                    end
                    local n = table.remove(v.shifts)
                    for j=i+1, i+n do Y[j] = Y[j-1] + v.period end
                    v = Y
                    
                elseif v.__class == "DeltasVector" then
                    t = string.format("DV start=%f, factor=%f", v.start, v.factor)
                    local Y = {v.factor * v.start}
                    for i, d in ipairs(v.deltas) do Y[i+1] = Y[i] + v.factor * d end
                    v = Y
                    
                else v = {"Error: unknown object type!"} end
            end

            if #v > 1 then v = "{ "..table.concat(v, ", ").." }"
            else v = v[1] end

            --display the value list
            tree:add(tvb(metrics.body[k].offset, metrics.body[k].length), string.format("%s (%s): %s", tostring(k), t, tostring(v)))

        else
            -- the value is a simple value
            tree:add(tvb(metrics.body[k].offset, metrics.body[k].length), string.format("%s (VALUE): %s", tostring(k), tostring(v)))
        end
        
    end
    
end

local function parse_response(tvb, tree, data, metrics)
        tree:add("Response", tvb(metrics.offset, metrics.length))
end


-- dissector function
function m3da_proto.dissector (tvb, pinfo, tree)
  pinfo.cols.protocol = m3da_proto.name

  -- validate packet length is adequate, otherwise quit
  if tvb:len() == 0 then return end

  -- Try to deserialize the M3DA packet
  local packet = tvb(0):string()
  local d = bysant.deserialize
  local metrics, data, length = d(packet)

  local err = data
  if err == "partial" then
      --print("partial packet, need reassembly")
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      return
  elseif not metrics then error(err) end

  if length <= #packet then --length is the offset in case of sucessful deserialization
    print("Probable error in the stream since there are several successive object from the same peer in the same stream")
  end

  -- DEBUG
  --p(data)

  -- create subtree for m3da
  tree = tree:add(m3da_proto, tvb(0))
  local subtree

  -- create subtree for the header
  subtree = tree:add(m3da_proto, tvb(metrics.header.offset, metrics.header.length), "Header")
  -- id
  if exist(data.header.id) then
    subtree:add(f_id, tvb(metrics.header.id.offset, metrics.header.id.length), data.header.id)
  end
  -- challenge
  if exist(data.header.challenge) then
      subtree:add(f_challenge, tvb(metrics.header.challenge.offset, metrics.header.challenge.length), data.header.challenge)
  end
  -- status
  if exist(data.header.status) then
      subtree:add(f_status, tvb(metrics.header.status.offset, metrics.header.status.length), data.header.status)
  end


  if exist(data.payload) and #data.payload > 0 then
    -- create subtree for the Payload
    subtree = tree:add(m3da_proto, tvb(metrics.payload.offset, metrics.payload.length), "Payload")
    -- Try to deserialize, may fail if the content is encrypted
    local s, payloadmetrics, payloaddata, payloadlength = pcall(d, data.payload)

    if not s or not payloadmetrics
            or type(payloaddata) ~= 'table'
            or (payloaddata.__class ~= "Response" and payloaddata.__class ~= "Message") then

        local ds
        if not payloadlength then ds=": deserialization error: ".. tostring(payloaddata) else ds="." end
        subtree:add(f_payload, tvb(metrics.payload.offset, metrics.payload.length), "Encrypted or corrupted payload"..ds)

    else -- Payload deserialization was successful !
        --DEBUG
        --p(data)
        --p(metrics)

        local function updateoffsets(t, d, s)
            for k, v in pairs(t) do
                if type(v) == "table" then updateoffsets(v, d)
                elseif k=="offset" then
                    if not s or t[k] >= s then -- Only add the delta if the offset if above step s
                        t[k] = v + d
                        -- TODO would need to update the size of the object when the offset is before the step and length make it finish after the step...
                    end
                end
            end
        end
        local o, d = table.remove(metrics.payload.suboffsets, 1):match("(%d*)\:(%d*)")
        updateoffsets(payloadmetrics, o+d)
        while #metrics.payload.suboffsets >= 1 do
            o, d = table.remove(metrics.payload.suboffsets, 1):match("(%d*)\:(%d*)")
            updateoffsets(payloadmetrics, d, o)
        end
        

        --p(payloaddata)
        --p(payloadmetrics)
        
        if payloaddata.__class == "Message" then parse_message(tvb, subtree, payloaddata, payloadmetrics)
        elseif payloaddata.__class == "Response" then parse_response(tvb, subtree, payloaddata, payloadmetrics) end
    end
  end


  -- create subtree for the Footer
  if exist(data.footer) and next(data.footer) then
    subtree = tree:add(m3da_proto, tvb(metrics.footer.offset, metrics.footer.length), "Footer")

    -- mac
    if exist(data.footer.mac) then
        local mac = stringtohex(data.footer.mac)
        subtree:add(f_mac, tvb(metrics.footer.mac.offset, metrics.footer.mac.length), mac)
    end
  end


end

-- Initialization routine
function m3da_proto.init()
end

-- register a chained dissector for port 44900
local tcp_dissector_table = DissectorTable.get("tcp.port")
dissector = tcp_dissector_table:get_dissector(44900)
  -- you can call dissector from function m3da_proto.dissector above
  -- so that the previous dissector gets called
tcp_dissector_table:add(44900, m3da_proto)