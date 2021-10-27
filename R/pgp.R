PKI.parse.pgp.key <- function(what, raw=FALSE)
  if (raw) .Call(PKI_parse_pgp_key, what, raw) else {
    res <- .Call(PKI_parse_pgp_key, what, raw)
    names(res) <- c("algorithm", "user.id", "key", "created")
    if (is.numeric(res$created))
      res$created <- .POSIXct(res$created)
    res
  }

PKI.readPGP <- function(what, raw=FALSE)
  lapply(PKI.pem.split(what), function(pem) {
    body <- PKI.pem.part(pem, TRUE, TRUE)
    PKI.parse.pgp.key(body, raw)
  })
