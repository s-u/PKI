\name{oid}
\alias{oid}
\alias{as.oid}
\alias{as.oid.default}
\alias{as.oid.integer}
\alias{as.character.oid}
\alias{as.integer.oid}
\alias{is.oid}
\alias{Ops.oid}
\alias{print.oid}
\title{
OBJECT IDENTIFIER Functions
}
\description{
  Object Identifiers (OIDs) are entities defined by international
  standards (ITU-T, ISO, IEC) used to identify objects. In the PKI
  context they are used for example to identify encyrption algorithms.
  Each root (first integer - see below) denotes the standards body
  governing the allocations.

  OIDs consist of a hierarchy of integers with each component having a
  meaning in the hierarchy. For example, the OID of the DER encoding is
  defined in the ITU-T X.680 standard as
  \code{joint-iso-itu-t(2) asn1(1) ber-derived(2) distinguished-encoding(1)}
  where the text before each integer describes its meaning in that
  context and the integer is the encoding of that meaning. So the OID
  itself would be in character form \code{"2.1.2.1"} (also called the dot
  notation introduced by IETF) and in R integer form
  \code{c(2, 1, 2, 1)}. Internally, OIDs are represented in their ASN.1
  encoding as raw vectors which is the way they are typically used
  in files or communication payload.

  The following functions are used to operate on OIDs.

  \code{oid} creates an OID.

  Coercion methods \code{as.integer} and \code{as.character} convert the
  OID into its numeric and textural form respectively. \code{as.oid} is
  a generic for convering objects into OIDs and is implemented for at
  least the above cases.

  \code{is.oid} returns \code{TRUE} if the object is an OID.  
}
\usage{
oid(x)

as.oid(x, ...) 
\method{as.oid}{default}(x, ...)
is.oid(x) 

\method{Ops}{oid}(e1, e2) 
\method{print}{oid}(x, ...) 

\method{as.character}{oid}(x, ...) 
\method{as.integer}{oid}(x, ...) 
}
\arguments{
  \item{x}{object to covert/create/check}
  \item{e1}{left-hand side argument for binary operators}
  \item{e2}{right-hand side arguemnt for binary operators}
  \item{...}{further arguments (currently unused)}
}
\details{
  The only allowed oparators on OIDs are \code{==} and \code{!=} which
  return \code{TRUE} or \code{FALSE}.

  The \code{oid(x)} constructor (and also the \code{as.oid} default
  method) support following types: scalar string (expected to be in
  dot-notation), integer vector, numeric vector (it is coerced to integer
  vector implicitly), raw vector (must be ASN.1 encoding of the OID).

  The S3 class of OID objects is \code{"oid"}. It consists of a raw
  vector repesenting the ASN.1 encoded OID (without the type
  specifier). An additional attribute \code{"type"} is set to \code{6L}
  for compatiblity with \code{\link{ASN1.encode}}.  
}
%\value{
%}
%\references{
%}
\author{
Simon Urbanek
}
%\note{
%}
\seealso{
\code{\link{ASN1.encode}}
}
\examples{
## RSA algorithm OID:
## iso(1) member-body(2) us(840) rsadsi(113549)
## pkcs(1) pkcs-1(1) rsaEncryption(1)
o <- oid("1.2.840.113549.1.1.1")
as.raw(o)
as.integer(o)
as.character(o)
as.oid(as.integer(o)) == o
is.oid(o)
(a <- ASN1.encode(o))
as.oid(ASN1.decode(a)) == o
}
\keyword{manip}
