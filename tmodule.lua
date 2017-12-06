local tracing = require 'tracing'
local _M = {}
function _M.new(self)
    return setmetatable({ test = "contenst"}, {__index=_M})
end

function _M.action(self)
    tracing:start_span("fortmodule")
    ngx.say(self.test)
    tracing:end_span()
end
return _M
