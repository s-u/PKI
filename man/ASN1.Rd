\name{ASN1}
\alias{ASN1}
\alias{ASN1.decode}
\alias{ASN1.encode}
\alias{ASN1.item}
\alias{ASN1.type}
\title{
  Functions for handling ASN.1 format (typically DER)
}
\description{
  \code{ASN1.decode} decodes \code{ASN.1} binary format into
  raw format chunks tagged with class types.

  \code{ASN1.encode} converts structured objects into
  \code{ASN.1} binary format.

  \code{ASN1.item} creates an item - basic object in
  structures that can be encoded using \code{ASN1.encode}.

  \code{ASN1.type} extracts the class type from an
  \code{ASN.1} item
}
\usage{
ASN1.decode(what)
ASN1.encode(what)
ASN1.item(what, type)
ASN1.type(what)
}
\arguments{
  \item{what}{object to decode/encode/query}
  \item{type}{class type of the item (integer value)}
}
\details{
  This is a suite of low-level tools to deal with ASN.1 (Abstract Syntax
  Notation One) binary formats DER, BER and CER. The tools were written
  specifically to handle the various DER-encoded key structures so it
  provides only a subset of the ASN.1 specification. They are used
  internally by the \code{PKI} poackage.

  \code{ASN1.decode} decodes the binary representation (as raw vector)
  into individual items. Sequences are convered into lists, all other
  objects are retained in their binary form and tagged with the integer
  class type - which can be obtained using \code{ASN1.type} function.

  \code{ASN1.encode} expects item (or a list of items) either created
  using \code{ASN1.decode} or \code{ASN1.item} and converts them into
  \code{DER} binary format.

  The result of \code{ASN1.encode(ASN1.decode(x))} will be \code{x} if
  \code{x} was in \code{DER} format.
}
\value{
  \code{ASN1.decode} returns either one item or a list.

  \code{ASN1.encode} returns a raw vector in DER format.

  \code{ASN1.type} returns an integer class type

  \code{ASN1.item} returns an ASN.1 item object
}
%\references{
%}
\author{
  Simon Urbanek
}
\note{
  \code{ASN1.encode} uses a fixed buffer for encoding which currently
  limits the total size of the resulting structure to 1MB.

  Only definite length forms are supported. The validity of individual
  items is not checked.
}
%\seealso{
%}
\examples{
# generate a small key
key <- PKI.genRSAkey(bits = 512L)

# extract private and public parts in DER format
prv <- PKI.save.key(key, format="DER")
pub <- PKI.save.key(key, private=FALSE, format="DER")

# parse the public key
x <- ASN1.decode(pub)
x
# the second element is the actual key
# as a bit string that's itself in DER
# two integers - modulus and exponent
# Note that this is in fact the pure PKCS#1 key format
ASN1.decode(x[[2]])

# encoding it back should yield the same representation since it is DER
stopifnot(identical(ASN1.encode(x), as.raw(pub)))

}
\keyword{manip}
