PKI.encrypt <- function(what, key, cipher = NULL, iv = NULL) .Call(PKI_encrypt, what, key, cipher, iv)

PKI.decrypt <- function(what, key, cipher = NULL, iv = NULL) .Call(PKI_decrypt, what, key, cipher, iv)
