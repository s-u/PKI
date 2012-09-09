\name{PKI.crypt}
\alias{PKI.crypt}
\alias{PKI.encrypt}
\alias{PKI.decrypt}
\title{
  PKI encryption/decryption functions
}
\description{
  \code{PKI.encrypt} encrypts a raw vector

  \code{PKI.decrypt} decrypts a raw vector
}
\usage{
PKI.encrypt(what, key)
PKI.decrypt(what, key)
}
\arguments{
  \item{what}{raw vector to encrypt/decrypt. It must not exceed the key
    size minus padding}
  \item{key}{key to use for encryption/decryption}
}
%\details{
%}
\value{
  Raw vector (encrypted/decrypted)
}
%\references{
%}
\author{
  Simon Urbanek
}
\note{
  Currently only RSA encryption is supported. Note that the payload
  should be very small since it must fit into the key size including
  padding. For example, 1024-bit key can only encrypt 87 bytes, while
  2048-bit key can encrypt 215 bytes.
}
\seealso{
  \code{\link{PKI.genRSAkey}}, \code{\link{PKI.pubkey}}
}
\examples{
  key <- PKI.genRSAkey(2048)
  x <- charToRaw("Hello, world!")
  e <- PKI.encrypt(x, key)
  y <- PKI.decrypt(e, key)
  stopifnot(identical(x, y))
  print(rawToChar(y))
}
\keyword{manip}
