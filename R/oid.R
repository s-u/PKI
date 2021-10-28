## OBJECT IDENTIFIERs from ASN.1
## We use the DER encoding for its internal representation
## Methods exist for as.character() and as.integer()
## to convert them tot the textual/unencoded form
## NOTE: we only support up to 31-bit OID components
## due to R integer representation limitations
## The "type" attribute is provided for direct
## compatibility with ASN.1 functions
oid <- function(x) {
  if (is.character(x)) {
    if (length(x) != 1)
      stop("OID character specification must be a single string")
    x <- as.integer(strsplit(x, ".", TRUE)[[1]])
  }
  ## the type attribute is for ASN.1 encoding
  structure(if (is.raw(x)) x else .Call(PKI_int2oid, x), type=6L, class="oid")
}

is.oid <- function(x) inherits(x, "oid")
as.oid <- function(x, ...) UseMethod("as.oid")
as.oid.default <- function(x, ...) oid(x)

as.character.oid <- function(x, ...) paste(.Call(PKI_oid2int, x), collapse=".")
as.integer.oid <-  function(x, ...) .Call(PKI_oid2int, x)

print.oid <- function(x, ...) {
  cat(" ObjectID: ", as.character(x), "\n", sep='')
  invisible(x)
}

Ops.oid <- function(e1, e2) {
  if (.Generic == "==") return(identical(as.integer(e1), as.integer(e2)))
  if (.Generic == "!=") return(!identical(as.integer(e1), as.integer(e2)))
  stop("Operator not meaningful for ObjectIDs")
}
