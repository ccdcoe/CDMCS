-- Copyright (C) 2014 Victor Julien <victor@inliniac.net>
--
-- You can copy, redistribute or modify this Program under the terms of
-- the GNU General Public License version 2 as published by the Free
-- Software Foundation.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- version 2 along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
-- 02110-1301, USA.
--
-- https://github.com/inliniac/surilua/blob/8b7595d7efb7af1a81b25fd95e43cfb5b66a0a2a/stats.lua
--
-- added "write to influxdb"
-- 2017 Hillar Aarelaid <hillar@aareliad.net>

function init (args)
    local needs = {}
    needs["type"] = "stats"
    return needs
end

function setup (args)
    SCLogInfo("setting up");
    start_time = os.time()
    top_pps = 0
    top_pps_nodrops = 0
    min_pps_drops = 0
end

function store_values (t, v)
    name = string.gsub(v["name"], "%.", "_");
    --print (name)
    if (t[name] ~= nil) then
        t[name] = t[name] + v["value"]
    else
        t[name] = v["value"]
    end
end

function store_pvalues (t, v)
    name = string.gsub(v["name"], "%.", "_");
    --print (name)
    if (t[name] ~= nil) then
        t[name] = t[name] + v["pvalue"]
    else
        t[name] = v["pvalue"]
    end
end

function store_diff (t, v)
    name = string.gsub(v["name"], "%.", "_");
    --print (name)
    local d = v["value"] - v["pvalue"]

    if (t[name] ~= nil) then
        t[name] = t[name] + d;
    else
        t[name] = d;
    end
end

local warnings ={ }

function warn (k, t, v)
    if warnings[k] == nil then
        SCLogWarning("(" .. t .. ") Warning -- " .. v)
        warnings[k] = true
    end

end

function flow_indicators (t, p, d)
    if (t.tcp_no_flow > 0) then
        warn("tcp_no_flow", "flow engine", "TCP packets w/o flow")
    end
    if (t.flow_emerg_mode_entered > 0) then
        warn("flow_emerg_mode_entered", "flow engine", "Emergency mode")
    end
end

function decoder_indicators (t, p, d)
    if (d.decoder_invalid > 0) then
        warn("decoder_invalid", "capture", "getting invalid packets: could be malformed traffic, but also capture problem")
    end
end

function tcp_indicators (t, p, d)
    if (t.tcp_syn > 0 and t.tcp_syn > (t.tcp_synack * 2)) then
        warn("tcp_syn_gt_synack", "capture", "SYN packets greatly outnumber SYN/ACK's: could be a scan/flood, but also a capture problem")
    end

    if (t.tcp_reassembly_gap > (t.tcp_sessions / 10)) then
        warn("tcp_reassembly_gap", "capture", "TCP data gaps detected in more than 10% of the sessions. Possible causes are packet loss (either at the host or SPAN/TAP, NIC offloading")
    end

    if (d.tcp_no_flow > 0 and d.tcp_no_flow > 25) then
        warn("tcp_no_flow", "flow engine", "TCP packets w/o associated flow increased by " .. d.tcp_no_flow .. ". Indication of flow engine in distress.")
    end
end

function capture_indicators (t, p, d)
    if (t.capture_merged_drops > t.decoder_pkts) then
        warn("massive_packet_loss", "capture", "massive packet loss detected. Dropping more packets than are processed")
    end

    --if (t.capture_merged_drops > 0 and t.capture_merged_drops < (t.decoder_pkts / 100)) then
    --    print "(perf analyzer) Minor packet loss of less than 1%."
    --end
end

-- do the actual drop counter merge
function capture_merge_drops_do(table)
    local drops = 0
    if table.capture_kernel_drops ~= nil then
        drops = drops + table.capture_kernel_drops
    end
    if table.capture_kernel_ifdrops ~= nil then
        drops = drops + table.capture_kernel_ifdrops
    end
    if table.capture_drops ~= nil then
        drops = drops + table.capture_drops
    end
    table.capture_merged_drops = drops
end

-- merge various capture 'drop' counters into one 'capture_merged_drops'
function capture_merge_drops (t, p, d)
    t.capture_merged_drops = 0
    p.capture_merged_drops = 0
    d.capture_merged_drops = 0

    capture_merge_drops_do(t)
    capture_merge_drops_do(p)
    capture_merge_drops_do(d)
end

--
-- POST to influxdb
--
local http = require("socket.http")

function write_to_influxdb(points, influx_host, influx_db)
  local host = influx_host or "10.244.1.190"
  local dbname = influx_db or "telegraf"
  if type(points) == "table" then
        points = table.concat(points, "\n")
  end
  local url = "http://" .. tostring(host) .. "/write?db=" .. tostring(dbname)
  return http.request(url, points)
end

--
--
--

function log(args)
    local t = { capture_drops = 0 }
    local p = { capture_drops = 0 }
    local d = { capture_drops = 0 }
    local points = {}

    for n, v in ipairs(args) do
        store_values(t,v)
        store_pvalues(p,v)
        store_diff(d,v)
    end

    capture_merge_drops (t, p, d)

    capture_indicators (t, p, d)
    flow_indicators (t, p, d)
    tcp_indicators (t, p, d)
    decoder_indicators (t, p, d)

    cur_time = os.time()
    elapsed_time = os.difftime(cur_time,start_time)
    start_time = os.time() -- reset

    bytesps_read = d.decoder_bytes / elapsed_time
    bitps_read = bytesps_read * 8
    mbitps_read = bitps_read / 1000000
    gbitps_read = mbitps_read / 1000

    pps_read = d.decoder_pkts / elapsed_time
    if pps_read > top_pps then
        top_pps = pps_read
    end
    pps_dropped = 0
    if d.capture_merged_drops ~= 0 then
        pps_dropped = d.capture_merged_drops / elapsed_time
        if min_pps_drops == 0 then
            min_pps_drops = pps_read
        else
            if pps_read < min_pps_drops then
                min_pps_drops = pps_read
            end
        end
    else
        if pps_read > top_pps_nodrops then
            top_pps_nodrops = pps_read
        end
    end

    str = string.format("Volume: %.3f Mbit/s %.3f Gbit/s", mbitps_read, gbitps_read);
    SCLogInfo(str);

    total = t.decoder_pkts + t.capture_merged_drops
    str = string.format("Packets: %d (%2.1f%%) processed (%d pps), %d dropped, %d drops/s (%2.1f%%)", t.decoder_pkts, (t.decoder_pkts / total * 100), pps_read, t.capture_merged_drops, pps_dropped, (t.capture_merged_drops / total * 100));
    SCLogInfo(str);

    str = string.format("TCP: sessions %d, with gaps %2.1f%%", t.tcp_sessions, ((t.tcp_reassembly_gap * 2) / t.tcp_sessions) * 100)
    SCLogInfo(str);
    table.insert(points, "tcp_sessions value=" .. t.tcp_sessions)
    local influx_response = write_to_influxdb(points)
    SCLogInfo(tostring(influx_response));


end

function deinit (args)
    str = string.format("Max PPS %d, max PPS w/o drops %d, lowest PPS with drops %d", top_pps, top_pps_nodrops, min_pps_drops)
    SCLogInfo(str);
end
