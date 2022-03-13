raw2hex <- function(what, sep, upper=FALSE)
  .Call(PKI_raw2hex, what, if (missing(sep)) NULL else sep, upper)

PKI.random <- function(n) .Call(PKI_random, n)

PKI.info <- function() .Call(PKI_engine_info)
