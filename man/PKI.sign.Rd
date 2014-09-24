\name{PKI.sign}
\alias{PKI.sign}
\alias{PKI.verify}
\title{
  PKI: sign content or verify a signature
}
\description{
  \code{PKI.sign} signs content using RSA with the specified hash function

  \code{PKI.verify} verifies a signature of RSA-signed content
}
\usage{
PKI.sign(what, key, hash = c("SHA1", "SHA256", "MD5"), digest)
PKI.verify(what, signature, key, hash = c("SHA1", "SHA256", "MD5"), digest)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{what}{raw vector: content to sign}
  \item{key}{RSA private key to use for signing; RSA public key or
    certificate to use for verification.}
  \item{hash}{hash function to use. "MD5" should not be used unless
    absolutely needed for compatibility as it is less secure.}
  \item{digest}{raw vector: it is possible to supply the digest of
    the content directly instead of specifying \code{what}.}
  \item{signature}{raw vector: signature}
}
\details{
  Objects are signed by computing a hash function digest (typically
  using \code{SHA1} hash function) and then signing the digest with a
  RSA key. Verification is done by computing the digest and then
  comparing the signature to the digest. Private key is needed for
  signing whereas public key is needed for verification.

  Both functions call \code{\link{PKI.digest}} on \code{what} if
  \code{digest} is not specified.
}
\value{
  \code{PKI.sign} signature (raw vector)

  \code{PKI.verify} logical: \code{TRUE} if the digest and signature
  match, \code{FALSE} otherwise
}
%\references{
%}
\author{
  Simon Urbanek
}
%\note{
%}
\seealso{
  \code{\link{PKI.pubkey}}, \code{\link{PKI.genRSAkey}},
  \code{\link{PKI.digest}}
}
\examples{
  key <- PKI.genRSAkey(2048)
  x <- charToRaw("My message to sign")
  sig <- PKI.sign(x, key)
  stopifnot(PKI.verify(x, sig, key))
}
\keyword{manip}
