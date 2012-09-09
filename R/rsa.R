PKI.load.privkey <- function(what, file) {
    if (!missing(file) && !missing(what)) stop("what and file are mutually exclusive")
    if (!missing(file)) {
        what <- con <- file(file, "r")
        on.exit(close(con))
      }
    if (inherits(what, "connection"))
        what <- readLines(what)
    if (is.character(what)) {
        i <- grep("-BEGIN RSA PRIVATE KEY-", what, fixed=TRUE)
        j <- grep("-END RSA PRIVATE KEY-", what, fixed=TRUE)
        if (length(i) >= 1L && length(j) >= 1L && i[1] < j[1])
            what <- base64enc::base64decode(what[(i + 1L):(j - 1L)])
        else
            stop("cannot find RSA private key in PEM format")
    }
    .Call(PKI_load_private_RSA, what)
}

PKI.genRSAkey <- function(bits=2048L) .Call(PKI_RSAkeygen, bits)
