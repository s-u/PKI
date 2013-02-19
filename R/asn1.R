ASN1.decode <- function(what) .Call(decode_ASN1, what)
ASN1.encode <- function(what) .Call(encode_ASN1, what)
ASN1.item <- function(what, type) {
  what <- as.raw(what)
  attr(what, "type") <- type
  what
}
ASN1.type <- function(what) attr(what, "type")
