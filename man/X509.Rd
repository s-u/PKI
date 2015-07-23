\name{X509}
\alias{X509}
\alias{PKI.load.cert}
\alias{PKI.verifyCA}
\alias{PKI.pubkey}
\alias{PKI.get.subject}
\alias{PKI.get.notBefore}
\alias{PKI.get.notAfter}
\title{
  Public Key Instraftructure (X509) functions
}
\description{
  \code{PKI.load.cert} creates a certificate obejct from a string,
  connection or file.

  \code{PKI.verifyCA} verifies a certificate against a given chain of
  trust.

  \code{PKI.pubkey} extracts public key from a certificate.  

  \code{PKI.get.subject} extracts the subject name from the certificate.
  
  \code{PKI.get.notBefore} extracts the notBefore field from the certificate.

  \code{PKI.get.notAfter} extracts the notAfter field from the certificate.

}
\usage{
PKI.load.cert(what, format = c("PEM", "DER"), file)
PKI.verifyCA(certificate, ca)
PKI.pubkey(certificate)
PKI.get.subject(certificate)
PKI.get.notBefore(certificate)
PKI.get.notAfter(certificate)
}
\arguments{
  \item{what}{string, raw vector or connection to load the certificate
    from}
  \item{format}{format used to encode the certificate}
  \item{file}{filename to load the certificate from - \code{what} and
    \code{file} are mutually exclusive}
  \item{certificate}{a certificate object (as returned by
    \code{PKI.load.cert})}
  \item{ca}{a certificate object of the Certificate Authority (CA) or a
    list of such objects if multiple CAs are involved}
}
%\details{
%}
\value{
  \code{PKI.load.code}: a certificate object

  \code{PKI.verifyCA}: \code{TRUE} is the certificate can be trusted,
  \code{FALSE} otherwise

  \code{PKI.pubkey}: public key object

  \code{PKI.get.subject}: string containing the subject information in
  one-line RFC2253 format but in UTF8 encoding instead of MBS escapes.
  NOTE: this is experimantal, we may choose to parse the contents and
  return it in native R form as a named vector instead.
  
  \code{PKI.get.notBefore}: POSIXct value containing the datetime 'notBefore'
  field fromt the certificate.  This represents the earliest time at which the
  certificate is valid.

  \code{PKI.get.notAfter}: POSIXct value containing the datetime 'notAfter'
  field fromt the certificate.  This represents the latest time at which the
  certificate is valid.
}
%\references{
%}
\author{
  Simon Urbanek
}
%\note{
%}
%\seealso{
%}
\examples{
  ca <- PKI.load.cert(file=system.file("certs", "RForge-ca.crt", package="PKI"))
  my.cert <- PKI.load.cert(readLines(system.file("certs", "demo.crt", package="PKI")))
  PKI.verifyCA(my.cert, ca)
  PKI.pubkey(my.cert)
  PKI.get.subject(my.cert)
  PKI.get.notBefore(my.cert)
  PKI.get.notAfter(my.cert)
}
\keyword{manip}
