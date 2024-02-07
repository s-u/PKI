raw2hex <- function(what, sep, upper=FALSE)
  .Call(PKI_raw2hex, what, if (missing(sep)) NULL else sep, upper)

PKI.random <- function(n) .Call(PKI_random, n)

PKI.info <- function() .Call(PKI_engine_info)

alphanum <- c(LETTERS, letters, 0:9)

PKI.genpass <- function(n=15, set=c(alphanum, ".", "/"), block=5, sep="-") {
    sb <- log(length(set), 2)
    if (as.integer(sb) != sb) warning("Set length is not a power of 2, set elements will have unequal probability")
    a <- set[as.integer(PKI.random(n)) %% length(set) + 1L]
    if (block > 0) {
        pad <- block - (n %% block)
        if (pad != block) a <- c(a, rep(" ", pad))
        m <- matrix(a, block)
        gsub(" ", "", paste(apply(m, 2, paste, collapse=''), collapse=sep))
    } else paste(a, collapse='')
}
