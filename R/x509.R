PKI.load.cert <- function(what, format = c("PEM", "DER"), file) {
    format <- match.arg(format)
    if (!missing(file) && !missing(what)) stop("what and file are mutually exclusive")
    binary <- isTRUE(format == "DER")
    if (!missing(file)) {
        what <- con <- file(file, if (binary) "rb" else "r")
        on.exit(close(con))
    }
    if (inherits(what, "connection"))
        what <- if (binary) readBin(what, raw(), chunk) else readLines(what)
    if (is.character(what)) {
        if (binary) stop("DER format selected but input is text")
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

PKI.get.subject <- function(certificate) .Call(PKI_get_subject, certificate)

PKI.get.notBefore <- function(certificate) {
    time_real <- .Call(PKI_get_notBefore, certificate)
    
    # To do the conversion in R, we would use
    # t <- strptime(aTime, format="%y%m%d%H%M%SZ", tz="GMT")
    # But that hardcodes the ASN1_TIME format, which won't always be correct
    
    return(as.POSIXct(time_real, tz="GMT", origin="1970-01-01"))
}

PKI.get.notAfter <- function(certificate) {
    time_real <- .Call(PKI_get_notAfter, certificate)
    return(as.POSIXct(time_real, tz="GMT", origin="1970-01-01"))
}

