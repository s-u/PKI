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

  \code{ASN1.item} creates an item - basic obejct in
  structures taht can be encoded using \code{ASN1.encode}.

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
  using \code{ASN1.decode} or \code{ASN1.item} and cinverts them into
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
  limits the total size of the resulting structre to 1MB.

  Only definite length forms are supported. The validity of individual
  items is not checked.
}
%\seealso{
%}
%\examples{
%}
\keyword{manip}
