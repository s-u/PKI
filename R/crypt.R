PKI.encrypt <- function(what, key) .Call(PKI_encrypt, what, key)

PKI.decrypt <- function(what, key) .Call(PKI_decrypt, what, key)
