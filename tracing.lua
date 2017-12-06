-- Copyright (C) Bing Bai (siklcut)  Wanda.

local cjson = require("cjson")
local ffi   = require("ffi")
local http  = require("resty.http")
local md5   = require("resty.md5")

-- for time we need microsend precision
-- c function wrapper
ffi.cdef[[
    typedef long time_t;
    typedef struct timeval {
        time_t tv_sec;
        time_t tv_usec;
    } timeval;
    int gettimeofday(struct timeval* t, void *tzp);
]]
local function gettimeofday()
    local time_st = ffi.new("timeval")
    ffi.C.gettimeofday(time_st, nil)
    return tonumber(time_st.tv_sec) * 1000000 + tonumber(time_st.tv_usec)
end

local function getusoftime()
    local time_st = ffi.new("timeval")
    ffi.C.gettimeofday(time_st, nil)
    return tonumber(time_st.tv_usec)
end

-- tracing const
local tracing_const_extra = {
    _FLAGS          = 'X-W-Flags',
    _SAMPLED        = 'X-W-Sampled',   
    _PARENTSPANID   = 'X-W-ParentSpanId',
    _SPANID         = 'X-W-SpanId',
}

local tracing_const = setmetatable({
    _TRACEID        = 'X-W-TraceId',
}, { __index = tracing_const_extra })

-- miroc const
local micro_const = 1000000

-- sampling rate
local sampling_rate = 128
local tracing_env   = "sit"

-- open or close
local open_tracing = 1

-- report source
local report_http_collector = 1
local report_by_file        = 2
local report_to_ngxlog      = 3
local report_to_syslog      = 4

local report_type = report_by_file

-- report to syslog
local function pack_syslog(msg)
    
    local date = os.date("%b %d %H:%M:%S", math.floor(ngx.now()))
    local ip = "openresty-tracing.com" 
    local tag = "openresty-tracing"

    -- facility 20 (ocal use 4) and serverity 6
    -- <facility + serverity> date hostname tag:msg
    -- see rfc3164
    return string.format("<166> %s %s %s:%s", date, ip, tag, msg) 
end

-- num to hex
local function num_to_hex(input)
   local b, k, out, i , d = 16, "0123456789ABCDEF", "", 0
   while input > 0 do
       i = i + 1
       input, d = math.floor(input/b), math.mod(input, b) + 1
       out = string.sub(k, d, d) .. out
   end
   return out
end

-- gen random id
local function gen_random_key(length)
    local us = getusoftime()
    local pid   = ngx.worker.pid()
    math.randomseed(us * pid)
    local max = math.pow(2, 32) 
    local min = math.pow(2, 33)  - 1
    local f1 = math.random(max, min) 
    local f2 = math.random(max, min) 
    return num_to_hex(f1) .. num_to_hex(f2)
end

-- function log error and report
local function log_error_report(func, errstr)
    ngx.log(ngx.ERR, string.format("[tracing] error occur at [%s]: %s", func, errstr))
        -- todo report error info
end

-- check execute
local function check_tracing(self)
    if open_tracing ~= 1 then
        return false
    end

    if ngx.ctx.tracing_context.sampled ~= 1 then
        return false
    end

    return true
end

-- module
local _M = setmetatable({

    -- base info
    _VERSION        = '0.01',
    _TRACE_VERSION  = 'openresty-1',

    -- report by http url
    _REPORT_URL     = {
        -- ["test"] = "http://10.209.34.167:10080/index",
        ["sit"]   = "http://twc.intra.sit.ffan.com",
        ["prod"]  = "http://twc.intra.ffan.com",
    },
    
    -- report by file
    _REPORT_FILE = "/var/wd/log/tracing/openresty",

    -- report domain socket
    -- _REPORT_DOMAIN_SOCKET = "unix:/var/run/tracing.sock"
    _REPORT_DOMAIN_SOCKET = "unix:/var/run/tracing.sock"

}, { __index = tracing_const })

-- change tracing status
function _M.stop_tracing(self)
    open_tracing = 0
end

-- change report type
function _M.modify_tracing_report_type(self, t)
    report_type = t
end

-- change tracing sampling rate
function _M.modify_tracing_sampling_rate(self, rate)
    sampling_rate = rate
end

-- set tracing env
function _M.set_tracing_env(self, env)
    if env ~= "sit" or env ~= "prod" then
        return false
    else
        tracing_env = env
        return true
    end
end

-- wrap create function by pcall
function _M.create_tracing_context(self, service_name)
    local status, obj = pcall(self._create_tracing_context, self, service_name)
    if status then
        -- return obj
        return
    else
        log_error_report("create_tracing_context", obj)
        -- return nil 
        return
    end
end

-- wrap record tracing context
function _M.record_tracing_context(self)
    if ngx.ctx.tracing_context ~= nil then
        local status, err = pcall(self._record_tracing_context, self)
        if status == false then
            log_error_report("record_tracing_context", err)
        end
    end
end

-- relation the content to ngx.ctx
-- create tracing context
function _M._create_tracing_context(self, service_name)

   -- check tracing status
   if open_tracing ~= 1 then
       -- return setmetatable({}, {__index=_M})
       return
   end
   
   -- retrieve tracing header
   local tracing_context = {}
   local headers = ngx.req.get_headers()
   if headers[self._SAMPLED] == "1" then
       tracing_context.sampled = 1
   elseif headers[self._SAMPLED] == "0" then
       tracing_context.sampled = 0
   else
       -- determine sampled or not
       math.randomseed(getusoftime())
       rate = math.random(0, sampling_rate)
       if rate == 0 then
           tracing_context.sampled = 1;
       else
           tracing_context.sampled = 0;
       end
   end

   -- check and gen others key
   if tracing_context.sampled == 1 then
       local base = {}
       for k, v in pairs(tracing_const) do
            if headers[v] ~= nil and headers[v] ~= ngx.null then
                base[v] = headers[v]
            else
                base[v] = gen_random_key(64)
            end
       end

       -- for sampled and flag
       tracing_context[self._SAMPLED] = "1"
       if headers[self._FLAGS] ~= nil then
           base[self._FLAGS] = headers[self._FLAGS]
       else
           base[self._FLAGS] = "0"
       end

       -- for span id
       -- current span change to "1.1.1.x" not random key id
       if headers[self._SPANID] ~= nil and headers[self._SPANID] ~= ngx.null then
           base[self._SPANID] = headers[self._SPANID]
       else
           base[self._SPANID] = "1"
       end

       -- record request info
       tracing_context.main = {}
       tracing_context.main.start_time = ngx.req.start_time()
       tracing_context.main.method = ngx.req.get_method()
       tracing_context.main.uri = ngx.var.host .. ngx.var.request_uri
       tracing_context.main.trace_id = base[self._TRACEID]
       tracing_context.main.span_id  = base[self._SPANID]

       if base[self._PARENTSPANID] ~= nil then
           tracing_context.main.parent_span_id = base[self._PARENTSPANID]
       end

       tracing_context.main.sampled         = base[self._SAMPLED]
       tracing_context.main.flags           = base[self._FLAGS] 
       tracing_context.main.endpoint    = {}
       tracing_context.main.endpoint.service_name = service_name
       tracing_context.main.endpoint.ipv4 = ngx.var.server_addr 
       tracing_context.main.endpoint.port = ngx.var.server_port


       -- for parent span id
       if headers[self._PARENTSPANID] ~= nil and headers[self._PARENTSPANID] ~= ngx.null then
           base[self._PARENTSPANID] = headers[self._PARENTSPANID]
       end

       -- record request info
       tracing_context.main = {}
       tracing_context.main.start_time = ngx.req.start_time()
       tracing_context.main.method = ngx.req.get_method()
       tracing_context.main.uri = ngx.var.host .. ngx.var.request_uri
       tracing_context.main.trace_id = base[self._TRACEID]
       tracing_context.main.span_id  = base[self._SPANID]

       if base[self._PARENTSPANID] ~= nil then
           tracing_context.main.parent_span_id = base[self._PARENTSPANID]
       end

       tracing_context.main.sampled         = base[self._SAMPLED]
       tracing_context.main.flags           = base[self._FLAGS] 
       tracing_context.main.endpoint    = {}
       tracing_context.main.endpoint.service_name = service_name
       tracing_context.main.endpoint.ipv4 = ngx.var.server_addr 
       tracing_context.main.endpoint.port = ngx.var.server_port

       -- alloc record info
       tracing_context.record = {}
        
   end
   -- return setmetatable({tracing_context=tracing_context}, {__index=_M})
   ngx.ctx.tracing_context = tracing_context
end

function _M._record_tracing_context(self)
    if check_tracing(self) then

        local start_time = ngx.ctx.tracing_context.main.start_time * micro_const
        local end_time  = gettimeofday()

        -- call back send function
        local function report_tracing(premature, tracing_context, start_time, end_time, host, ip, report_type, tracing_env)

            local main_span = {}

            -- build main span
            main_span.timestamp  = start_time
            main_span.traceId    = tracing_context.main.trace_id
            main_span.duration   = end_time - start_time
            main_span.id         = tracing_context.main.span_id
            if tracing_context.main.parent_span_id ~= nil then
                main_span.parentId   = tracing_context.main.parent_span_id
            end
            main_span.name       = tracing_context.main.method
            main_span.version    = self._TRACE_VERSION
            main_span.annotations =  {} 
            table.insert(main_span.annotations, {
                value = "ss",
                timestamp = start_time,
                endpoint  = tracing_context.main.endpoint
            })
            table.insert(main_span.annotations, {
                value = "sr",
                timestamp = end_time,
                endpoint  = tracing_context.main.endpoint
            })

            main_span.binaryAnnotations =  {} 
            table.insert(main_span.binaryAnnotations, {
                key = "http.url",
                value = tracing_context.main.uri,
                endpoint = tracing_context.main.endpoint,
            })

            table.insert(tracing_context.record, main_span)

            -- record tracing to http server collector
            -- ngx.log(ngx.INFO, "tracing_context.main:" .. (tracing_context.base[self._TRACEID]))
            cjson.encode_empty_table_as_object(false)
            local record = cjson.encode(tracing_context.record)

            -- report by flume http collector
            if report_type == 1 then
                local json_format = cjson.encode({
                    hostname = ip, 
                    project = "openrestyTrace",
                    timestamp = start_time/1000,
                    body    = record
                })
                local body_t = {} 
                table.insert(body_t, {
                    ["header"] = {
                        ["timestamp"] = start_time/1000,
                        ["host"]    = host 
                    },
                    ["body"] = json_format
                })
                local body = cjson.encode(body_t)
                local report_url = self._REPORT_URL[tracing_env]
                local client = http:new()
                local ok, code, headers, status, body = client:request {
                    -- current is for test
                    url     = report_url,
                    timeout = 300,
                    method  = "POST",
                    headers = {
                        ["Content-Type"] = "application/json",
                    },
                    body    = body
                }
                ngx.log(ngx.WARN, string.format("openresty tracing detail send status result:%s, code:%s, status:%s", tostring(ok), tostring(code), tostring(status)))

            -- report by file
            elseif report_type == 2 then
                local f = io.popen('[ -e "' .. self._REPORT_FILE .. '" ] && echo "Found" || echo "NOT"') 
                local r = f:read('*a')
                f:close()
                -- check dir exist
                if ret ~= "Found" then
                    -- if mkdir error, we abort it
                    os.execute('mkdir -p ' .. self._REPORT_FILE)
                end

                -- write log to file
                local date = os.date("%Y%m%d")
                local file_name = string.format("/tracing-%s.log", date)
                local content =  record .. "\n"
                local file = io.open(self._REPORT_FILE .. file_name, "a+")
                io.output(file)
                io.write(content)
                io.close(file)

            -- report by unix socket
            elseif report_type == 3 then
                ngx.log(ngx.INFO, record)
            elseif report_type == 4 then
                -- not use tcp, use udp
                -- local sock = ngx.socket.tcp()
                -- -- set timeout to 300 ms
                -- sock:settimeout(300)
                -- local message = pack_syslog(record)
                -- local ok, err = sock:connect(self._REPORT_DOMAIN_SOCKET)
                -- if not ok then
                --     ngx.log(ngx.WARN, string.format("tracing report to unix domain connect err:%s", err))
                --     return
                -- end
                -- local bytes, err = sock:send(message)
                -- if not bytes then
                --     ngx.log(ngx.WARN, string.format("tracing report ot unix domain send err:%s", err))
                -- end
                -- sock:close()

                local sock = ngx.socket.udp()
                local ok, err = sock:setpeername(self._REPORT_DOMAIN_SOCKET)
                if not ok then
                    ngx.log(ngx.WARN, string.format("tracing report to unix domain connect err:%s", err))
                end

                local message = pack_syslog(record)
                local ok, err = sock:send(message)
                if not ok then
                    ngx.log(ngx.WARN, string.format("tracing report ot unix domain send err:%s", err))
                end

                sock:close()
            end
        end

        -- start timer
        ngx.timer.at(0.1, report_tracing, ngx.ctx.tracing_context, start_time, end_time, ngx.var.host, ngx.var.server_addr, report_type, tracing_env)
    end
end

-- start span
-- return span ctx, after use this to tracing
function _M.start_span(self, name)
    if check_tracing(self) then
        local tracing_context = ngx.ctx.tracing_context
        if tracing_context.record ~= nil then

            -- build record start span, detail format you can see read me
            local span = {}
            local start_tt  = gettimeofday() 
            span.timestamp  = start_tt
            span.traceId    = tracing_context.main.trace_id
            span.parentId   = tracing_context.main.span_id

            -- generate span id
            local index = #tracing_context.record   
            span.id         = tracing_context.main.span_id .. "." .. tostring(index + 1)

            span.name       = name
            span.version    = self._TRACE_VERSION
            span.annotations =  {} 
            span.binaryAnnotations =  {} 

            table.insert(span.annotations, {
                value = "cs",
                timestamp = start_tt,
                endpoint = tracing_context.main.endpoint
            })
            table.insert(tracing_context.record, span)
        end
    end
end

-- end span
-- return nothing
function _M.end_span(self)
    if check_tracing(self) then
        local tracing_context = ngx.ctx.tracing_context
        if tracing_context.record ~= nil then

            -- check here is a start span
            -- if here is not a start span not add anything
            local index = #tracing_context.record   
            if index == 0 then
                return
            end

            if (#tracing_context.record[index].annotations == 1) then
                local end_tt  = gettimeofday()
                table.insert(tracing_context.record[index].annotations, {
                    value = "cr",
                    timestamp = end_tt,
                    endpoint = tracing_context.main.endpoint,
                })
            -- todo determine if we need to clear the one annotations

            end
        end
    end
end

-- add standard binnary_annotations
function _M.span_add_standard_ba(self, key, value)
    if check_tracing(self) then
        local tracing_context = ngx.ctx.tracing_context
        if tracing_context.record ~= nil then

            local index = #tracing_context.record   
            if index == 0 then
                return false
            end

            local support_key = {
                ["db.statement"]        = 1, 
                ["db.type"]             = 1, 
                ["db.instance"]         = 1, 
                ["http.status"]         = 1, 
                ["http.url"]            = 1,
                ["http.response"]       = 1,
                ["error"]               = 1,
            }

            if support_key[key] ~= nil then
                table.insert(tracing_context.record[index].binaryAnnotations, {
                    key = key,
                    value = value,
                    endpoint = tracing_context.main.endpoint,
                }) 
            else
                return false
            end
        end
    end
end

function _M.span_add_app_ba(self, key, value)
    if check_tracing(self) then
        local tracing_context = ngx.ctx.tracing_context
        if tracing_context.record ~= nil then

            local index = #tracing_context.record   
            if index == 0 then
                return
            end

            table.insert(tracing_context.record[index].binaryAnnotations, {
                key = key,
                value = value,
                endpoint = tracing_context.main.endpoint,
            }) 
        end
    end
end

-- span add server address
function _M.span_add_sa(self, service_name, ip, port)
    if check_tracing(self) then
        local tracing_context = ngx.ctx.tracing_context
        if tracing_context.record ~= nil then

            local index = #tracing_context.record   
            if index == 0 then
                return
            end

            table.insert(tracing_context.record[index].binaryAnnotations, {
                key = "sa",
                value = "true",
                endpoint = {
                    service_name = service_name,
                    ipv4         = tostring(ip),
                    port         = tonumber(port),
                },
            }) 
        end
    end
end

-- export http request header
-- these must after start_span
-- return table
function _M.export_trace_header(self)
    if check_tracing(self) then
        local tracing_context = ngx.ctx.tracing_context
        if tracing_context.record ~= nil then
            local index = #tracing_context.record   
            if index == 0 then
                return {}, false
            end

            if tracing_context.record[index].id ~= nil then
                local span_id = tracing_context.record[index].id
                return {
                    [tracing_const._TRACEID]        = tracing_context.main.trace_id,
                    [tracing_const._PARENTSPANID]   = tracing_context.main.span_id,
                    [tracing_const._SPANID]         = span_id,
                    [tracing_const._SAMPLED]        = tracing_context.sampled,
                    [tracing_const._FLAGS]          = tracing_context.main.flags,
                }, true
            else
                return {}, false
            end
        else
            return {}, false
        end
    -- first check open tracing
    elseif open_tracing ~= 1 then
        return {},true
    -- second check sampled
    elseif ngx.ctx.tracing_context.sampled ~= 1  then
        return {
            [tracing_const._SAMPLED] = 0
        }, true
    end
end

return _M
