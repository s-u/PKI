PKI.load.key <- function(what, format=c("PEM", "DER"), private, file) {
    if (!missing(file) && !missing(what)) stop("what and file are mutually exclusive")
    format <- match.arg(format)
    if (missing(private)) private <- NA
    either <- (length(private) > 0) && isTRUE(all(is.na(private)))
    private <- isTRUE(private)
    bin <- isTRUE(format == "DER")
    if (!missing(file)) {
        what <- con <- file(file, if (bin) "rb" else "r")
        on.exit(close(con))
    }
    if (inherits(what, "connection"))
        what <- if (bin) readBin(what, raw(), 65536L) else readLines(what)
    if (is.character(what)) {
        if (either || private) {
            i <- grep("-BEGIN RSA PRIVATE KEY-", what, fixed=TRUE)
            j <- grep("-END RSA PRIVATE KEY-", what, fixed=TRUE)
            if (length(i) >= 1L && length(j) >= 1L && i[1] < j[1]) {
                what <- base64enc::base64decode(what[(i + 1L):(j - 1L)])
                private <- TRUE
            } else {
                if (private)
                    stop("cannot find RSA private key in PEM format")
            }
        }
        if (!private) {
            i <- grep("-BEGIN PUBLIC KEY-", what, fixed=TRUE)
            j <- grep("-END PUBLIC KEY-", what, fixed=TRUE)
            if (length(i) >= 1L && length(j) >= 1L && i[1] < j[1])
                what <- base64enc::base64decode(what[(i + 1L):(j - 1L)])
            else {
                if (either)
                    stop("cannot find either public or private RSA key in PEM format")
                else
                    stop("cannot find public RSA key in PEM format")
            }
        }
    }
    if (private)
      .Call(PKI_load_private_RSA, what)
    else
      .Call(PKI_load_public_RSA, what)
}

PKI.save.key <- function(key, format=c("PEM", "DER"), private=NA, target) {
  der <- .Call(PKI_extract_key, key, private)
  format <- match.arg(format)
  if (isTRUE(format == "PEM")) {
    guard <- if (inherits(der, "public.key.DER")) c("-----BEGIN PUBLIC KEY-----","-----END PUBLIC KEY-----") else c("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
    pem <- c(guard[1], base64enc::base64encode(der, 64), guard[2])
    if (!missing(target)) {
      if (is.character(target)) {
        target <- file(target, "w")
        on.exit(close(target))
      }
      if (inherits(target, "connection")) writeLines(pem, target)
    }
    return (pem)
  }

  if (!missing(target)) {
    if (is.character(target)) {
      target <- file(target, "wb")
      on.exit(close(target))
    }
    if (inherits(target, "connection")) writeBin(der, target)
  }
  return (der)
}

PKI.genRSAkey <- function(bits=2048L) .Call(PKI_RSAkeygen, bits)

PKI.sign <- function(what, key, hash=c("SHA1", "MD5"), digest) {
  if (!missing(digest) && !missing(what))
    stop("what and digest are mutually exclusive")
  if (missing(digest))
    digest <- PKI.digest(what, hash)
  hash <- pmatch(hash, c("SHA1", "MD5"))[1]
  if (is.na(hash)) stop("invalid hash specification")
  .Call(PKI_sign_RSA, digest, hash, key)
}

PKI.verify <- function(what, signature, key, hash=c("SHA1", "MD5"), digest) {
  if (!missing(digest) && !missing(what))
    stop("what and digest are mutually exclusive")
  if (missing(digest))
    digest <- PKI.digest(what, hash)
  hash <- pmatch(hash, c("SHA1", "MD5"))[1]
  if (is.na(hash)) stop("invalid hash specification")
  .Call(PKI_verify_RSA, digest, hash, key, signature)
}

PKI.mkRSApubkey <- function(modulus, exponent=65537L, format = c("DER", "PEM", "key")) {
  format <- match.arg(format)
  if (inherits(modulus, "bigz") || !is.raw(modulus)) modulus <- as.BIGNUMint(modulus)
  if (inherits(exponent, "bigz") || !is.raw(exponent)) exponent <- as.BIGNUMint(exponent)
  der <- ASN1.encode(list(list(ASN1.item(as.raw(c(0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1)), 6L),
                               ASN1.item(raw(0), 5L)),
                          ASN1.item(ASN1.encode(list(ASN1.item(modulus, 2L), ASN1.item(exponent, 2L))), 3L)))
  if (format == "DER") return(der)
  if (format == "PEM") return(c("-----BEGIN PUBLIC KEY-----", base64enc::base64encode(der, 64), "-----END PUBLIC KEY-----"))
  .Call(PKI_load_public_RSA, der)
}

PKI.load.OpenSSH.pubkey <- function(what, first=TRUE, format = c("DER", "PEM", "key")) {
  format <- match.arg(format)
  if (inherits(what, "connection")) what <- readLines(what)
  what <- what[grep("^ssh-rsa ", what)]
  if (length(what)) {
    if (isTRUE(first) && length(what) > 1L)
      what <- what[1L]
    keys <- lapply(strsplit(what, " "), function(ln) {
      c <- rawConnection(base64decode(ln[2]), "rb")
      l <- readBin(c, 1L, endian="big")
      s <- rawToChar(readBin(c, raw(), l))
      l <- readBin(c, 1L, endian="big")
      exp <- readBin(c, raw(), l)
      l <- readBin(c, 1L, endian="big")
      mod <- readBin(c, raw(), l)
      close(c)
      PKI.mkRSApubkey(mod, exp, format=format)
    })
    if (isTRUE(first))
      keys[[1]]
    else
      keys
  } else list()
}
