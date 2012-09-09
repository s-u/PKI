PKI.load.cert <- function(what, format="PEM", file) {
    if (!missing(file) && !missing(what)) stop("what and file are mutually exclusive")
    if (!missing(file)) {
        what <- con <- file(file, "r")
        on.exit(close(con))
      }
    if (inherits(what, "connection"))
        what <- readLines(what)
    if (is.character(what)) {
        i <- grep("-BEGIN CERTIFICATE-", what, fixed=TRUE)
        j <- grep("-END CERTIFICATE-", what, fixed=TRUE)
        if (length(i) >= 1L && length(j) >= 1L && i[1] < j[1])
            what <- base64enc::base64decode(what[(i + 1L):(j - 1L)])
        else
            stop("invalid PEM format")
    }
    .Call(PKI_load_DER_X509, what)
}

PKI.verifyCA <- function(certificate, ca) .Call(PKI_verify_cert, ca, certificate)

PKI.pubkey <- function(certificate) .Call(PKI_cert_public_key, certificate)
