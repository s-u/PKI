\name{PKI.sign.tar}
\alias{PKI.sign.tar}
\alias{PKI.verify.tar}
\title{
  Functions for signing and verification of tar files
}
\description{
  \code{PKI.sign.tar} appends a signature to a tar file

  \code{PKI.verify.tar} verifies the signature in a tar file
}
\usage{
PKI.sign.tar(tarfile, key, certificate, output = tarfile)
PKI.verify.tar(tarfile, key, silent = FALSE, enforce.cert = FALSE)
}
\arguments{
  \item{tarfile}{string, file name of the file to sign}
  \item{key}{\code{PKI.sign.tar}: private key to use for signing;
    \code{PKI.verify.tar}: optional, public key to use for verification}
  \item{certificate}{optional, certificate to embed in the signature
    with the public key matching \code{key}. If not present the
    signature will only contain the public key.}
  \item{output}{file name, connection or raw vector determining how to
    store the signed tar file}
  \item{silent}{if \code{TRUE} then no warning are generatod, otherwise
    a warning is issues for failed verification describing the reason
    for failure}
  \item{enforce.cert}{if \code{TRUE} then a certificate is required in
    the signature. It can be also set to a valid certificate in which
    case the public key of the certificate in the signature must also
    match the public key in the supplied certificate.}
}
\details{
  \code{PKI.tar.sign} adds extra entry \code{.signature} with the
  signature based on the contents of the \code{tarfile}. Note that
  any existing signatures are retained. \code{key} is a mandatory
  private key used to sign the content. \code{certificate} is optional
  but if present, it will be embedded in the signature.

  The \code{tarfile} can be in compressed form (gzip, bzip2 or xz) in
  which case it is decompressed internally before the signature is
  applied. If \code{output} is a file name then the same compression is
  applied to the output, otherwise the output is uncompressed.

  \code{PKI.verify.tar} retrieves the last \code{.signature} entry from
  the tar file (if \code{tarfile} is a file name then the same
  compression auto-detection is applied as above) and
  verifies the signature against either the supplied (public) \code{key}
  or against the key or certificate stored in the signature. The result
  is \code{TRUE} or \code{FALSE} except when \code{enforce.cert} is
  set. In that case the result is the certificate contained in the
  signature if the validation succeeded (and thus it can be further
  verified against a chain of trust), otherwise \code{FALSE}.
}
%\value{
%}
%\references{
%}
\author{
  Simon Urbanek
}
\note{
  The signature format is ASN.1 DER encoded as follows:

  \code{SEQ(signature BITSTRING, subjectPublicKeyInfo, Certificate[opt])}
  
  The \code{subjectPublicKeyInfo} can be \code{NULL} in which case the
  certificate must be present (in X.509 DER format).

  The signature is appended as tar entry named
  \code{.signature}. However, terminating blocks are not removed from
  the file, so the signature is placed after the EOF blocks and thus
  doesn't affect extraction.
}
%\seealso{
%}
%\examples{
%}
\keyword{manip}
