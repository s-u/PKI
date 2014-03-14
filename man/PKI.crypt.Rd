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
PKI.encrypt(what, key, cipher = NULL)
PKI.decrypt(what, key, cipher = NULL)
}
\arguments{
  \item{what}{raw vector to encrypt/decrypt. It must not exceed the key
    size minus padding}
  \item{key}{key to use for encryption/decryption}
  \item{cipher}{cipher to use for encryption/decryption}
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
  The cipher is optional for key objects that already contain the
  cipher information such as RSA keys (in fact it is ignored in that
  case).

  Supported symmetric ciphers are \code{"aes128ecb"} (alias
  \code{"aes128"}), \code{"aes128cbc"}, \code{"aes128ofb"},
  \code{"aes256ecb"} (alias \code{"aes256"}), \code{"aes256cbc"} and
  \code{"aes256ofb"}. PKCS padding is used to fill up to the block size.

  Note that the payload for RSA encryption should be very small since
  it must fit into the key size including padding. For example, 1024-bit
  key can only encrypt 87 bytes, while 2048-bit key can encrypt 215
  bytes. Therefore a typical use is to use RSA to transfer a symmeric
  key to the peer and subsequently use symmetric ciphers like AES for
  encryption of larger amounts of data.
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

  ## AES symmetric - use SHA1 to support arbitrarily long key strings
  key <- PKI.digest(charToRaw("hello"))
  ae <- PKI.encrypt(x, key, "aes256")
  ae
  ad <- PKI.decrypt(ae, key, "aes256")
  stopifnot(identical(x, ad))
}
\keyword{manip}
