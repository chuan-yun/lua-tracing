openresty-tracing sdk
-----------------------

install
-----------------------
contact us for download sdk

init
-----------------------
`path` is where you locate sdk

include package path
```lua
lua_package_path "/$path/?.lua;;";

```

require package

```lua
local tracing = require "tracing"
```


tracing config
----------------------
lua tracing default sampling rate is 128.

you can use modify_tracing_sampling_rate and the function after to change it.

exp.
```lua
-- set tracing sampling
tracing:modify_tracing_sampling_rate(256)

-- set tracing env (not use now)
tracing:set_tracing_env("prod" or "sit")

-- stop tracing default open
tracing:stop_tracing()

-- change send source
-- 1 to http_collector
-- 2 to file
-- 3 to ngx log
-- 4 to syslog
-- the type need to set some other configs
-------------------------------------------------
-- exp. syslog need set syslog config
-- $AddUnixListenSocket /var/run/tracing.sock
-- $InputUnixListenSocketCreatePath on 
-- local4.*     /var/log/tracing.log 
-------------------------------------------------
tracing:modify_tracing_report_type(4)

```
`NOTICE` the config funciton `MUST` int the `init_by_lua` or `init_by_lua_block`  or `init_by_lua_file` phase. detail see [lua-variable-scope](https://github.com/openresty/lua-nginx-module#lua-variable-scope)

how to use
-----------------------

### first, create tracing context

exp. 
```lua
tracing:create_tracing_context($serviceName)
```

### second, wrap your code by start span and end end span

exp.
```lua
tracing:start_span($spanName)
your code 
tracing:end_span()
```

### third, add annotations as particular as possible.

we offer two method to record annotations.

if you record standard binnary annotions,
you should use `span_add_standard_ba(k, v)`.
the method must after `start_span`.

parameter $1 is the set of key, which contain the keys after:

- `db.statement` the sql/statement you exec.
- `db.type`      the type of db you use, exp. `redis`, `mysql`, `memcached` and so on.
- `sb.instance`  the db instance you select.
- `http.status`  the http status code.
- `http.url`     the http url you request.
- `http.response` the http response for record, `NOTE`, if you not need trace reponse, not set, if you need it , must trucate the response size!!!!!!!!
- `error`         if you record the span has error , you should add error.

parameter $2 the content you record.
exp.
```lua
-- mysql
tracing:span_add_standard_ba("db.type", "mysql")
tracing:span_add_standard_ba("db.instance", "test")
tracing:span_add_standard_ba("db.statement", "select * from users")

-- http
tracing:span_add_standard_ba("http.status", "200")
tracing:span_add_standard_ba("http.url", "http://api.ffan.com")

-- error
tracing:span_add_standard_ba("error", "can not resolve host")

```

if you want add annotations which you custom, you should use
`span_add_app_ba(k, v)`.
exp.
```lua
tracing:span_add_app_ba("key", "data what you want")
```

here is  the special,  if here is remote call, like `http`,`mysql`, `redis`, you `must` add  `sa` for backend to analysis the server you call.
`span_add_sa(servceName, ip, port)`
exp.
```lua
-- http
tracing:span_add_sa("risk", "192.168.56.1", 8080)

-- mysql
tracing:span_add_sa("mysql", "172.15.121.1", 3306)

```

### merge http header

`NOTICE` full stack trace system, trace request by special heaer, if you dial a http request, you `should` merge trace http header to your header, we provide method to export header.
`export_trace_header()`
the method must after `start_span`.
exp.
```lua
-- export header table
local trace_header = tracing:export_trace_header()

http_client.set_headers(trace_header)
http_client.request(...)

```

### finnal, end main tracing and send tracing info
exp.
```lua


CHANGE
-------------------------------
span_id change to '1.1.x', not random 64bit id

tracing:record_tracing_context()