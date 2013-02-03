\name{RSA}
\alias{RSA}
\alias{PKI.genRSAkey}
\alias{PKI.load.key}
\alias{PKI.save.key}
\title{
  PKI functions handling RSA keys 
}
\description{
  \code{PKI.load.key} loads an RSA key in PKCS#1 PEM or DER format.

  \code{PKI.save.key} creates a PEM or DER representation of a RSA key.
  
  \code{PKI.genRSAkey} generates RSA public/private key pair.
}
\usage{
PKI.load.key(what, format = c("PEM", "DER"), private, file)
PKI.save.key(key, format = c("PEM", "DER"), private, target)
PKI.genRSAkey(bits = 2048L)
}
\arguments{
  \item{what}{string, raw vector or connection to load the key from}
  \item{key}{RSA key object}
  \item{format}{format - PEM is ASCII (essentially base64-encoded DER
    with header/footer), DER is binary}
  \item{private}{logical, whether to use the private key (\code{TRUE}),
    public key (\code{FALSE}) or whichever is available (\code{NA} or missing).}
  \item{file}{filename to load the key from - \code{what} and
    \code{file} are mutually exclusive}
  \item{target}{optional connection or a file name to store the result
    in. If missing, the result is just returned form teh function as
    either a character vector (PEM) or a raw vector (DER).}
  \item{bits}{size of the generated key in bits. Must be \code{2 ^ n}
    with integer \code{n > 8}.}
}
%\details{
%}
\value{
  \code{PKI.load.key}: private or public key object

  \code{PKI.save.key}: raw vector (DER format) or character vector (PEM
  format).
  
  \code{PKI.genRSAkey}: private + public key object 
}
%\references{
%}
\author{
  Simon Urbanek
}
\note{
  The format for private keys in PEM is PKCS#1, but for public keys it
  is X.509 SubjectPublicKeyInfo (certificate public key). This is
  consistent with OpenSSL RSA command line tool which uses the same
  convention.
}
\seealso{\code{\link{PKI.encrypt}}, \code{\link{PKI.decrypt}}, \code{\link{PKI.pubkey}}}
\examples{
key <- PKI.genRSAkey(bits = 2048L)
priv.pem <- PKI.save.key(key)
pub.pem <- PKI.save.key(key, private = FALSE)
pub.k <- PKI.load.key(pub.pem)
x <- PKI.encrypt(charToRaw("Hello, world!"), pub.k)
rawToChar(PKI.decrypt(x, key))
}
\keyword{manip}
