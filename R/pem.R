PKI.pem.split <- function(what) .Call(PKI_PEM_split, what)

PKI.pem.part <- function(what, body=TRUE, decode=FALSE) .Call(PKI_PEM_part, what, body, decode)

