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
PKI.encrypt(what, key, cipher = NULL, iv = NULL)
PKI.decrypt(what, key, cipher = NULL, iv = NULL)
}
\arguments{
  \item{what}{raw vector to encrypt/decrypt. It must not exceed the key
    size minus padding}
  \item{key}{key to use for encryption/decryption}
  \item{cipher}{cipher to use for encryption/decryption}
  \item{iv}{initialization vector for ciphers that use it (e.g.,
  CBC). \code{NULL} corresponds to all-zeroes IV, otherwise must be
  either a string or a raw vector with sufficiently many bytes to
  match the IV length for the cipher.}
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

  Supported symmetric ciphers are AES-128, AES-256 and BF
  (blowfish). Each cipher can be used in CBC (default), ECB or OFB
  modes which are specified as suffix, so \code{"aes256ofb"} would
  specify AES-256 in OFB mode. Case and non-alphanumeric characters are
  ignored, so the same could be specified as \code{"AES-256-OFB"}.
  PKCS padding is used to fill up to the block size. Analogously, PKCS
  padding is expected when decoding.

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

  ## AES symmetric - use SHA256 to support arbitrarily long key strings
  key <- PKI.digest(charToRaw("hello"), "SHA256")
  ae <- PKI.encrypt(x, key, "aes256")
  ae
  ad <- PKI.decrypt(ae, key, "aes256")
  stopifnot(identical(x, ad))
}
\keyword{manip}
