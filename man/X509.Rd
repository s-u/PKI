\name{X509}
\alias{X509}
\alias{PKI.load.cert}
\alias{PKI.verifyCA}
\alias{PKI.pubkey}
\alias{PKI.get.subject}
\alias{PKI.get.cert.info}
\title{
  Public Key Instraftructure (X509) functions
}
\description{
  \code{PKI.load.cert} creates a certificate object from a string,
  connection or file.

  \code{PKI.verifyCA} verifies a certificate against a given chain of
  trust.

  \code{PKI.pubkey} extracts public key from a certificate.  

  \code{PKI.get.subject} extracts the subject name from the certificate.

  \code{PKI.get.cert.info} decodes information from the certificate.
}
\usage{
PKI.load.cert(what, format = c("PEM", "DER"), file)
PKI.verifyCA(certificate, ca, default = FALSE, partial = FALSE)
PKI.pubkey(certificate)
PKI.get.subject(certificate)
PKI.get.cert.info(certificate)
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
    list of such objects if a chain of certificates is involved}
  \item{default}{logical, if \code{TRUE} then root CAs known to OpenSSL
    will be added to the trust store. In that case \code{ca} can also
    be \code{NULL} if the certificate is directly signed by the root
    CA (very uncommon).}
  \item{partial}{logical, if \code{TRUE} then the CAs listed in
   \code{ca} are trusted even if they are neither root nor self-signed
   CAs.}
}
\details{
  \code{PKI.verifyCA} is used to verify the validity of a certificate
  by following a chain of trust. In the most simple case the
  certificate was issued by a certificate authority (CA) directly,
  which has a self-signed certificate. This is typically the case when
  you (or your organization) have created your own CA for internal use.
  In that case you only need to supply that CA's certificate to
  \code{ca} and that's it. It is also possible that your self-signed
  CA issued an intermediate certificate - if that is the case then pass
  a list of both certificates (order doesn't matter) to \code{ca}.

  Another use case is that you have a certificate which has been issued
  by publicly trusted CA - this is commonly the case with SSL
  certificates used by web servers. In that case, the chain doesn't
  end with an internal self-signed certificate, but instead it will
  end with a publicly known root CA. OpenSSL manages a list of such
  trusted CAs and you can check against them with
  \code{default=TRUE}. However, in most cases your certificate won't
  be issued directly by a root CA, but by an intermetiate authority so
  you have to pass the intermediate certificate(s) in the \code{ca}
  argument.

  Finally, it is sometimes possible that the default list of trusted
  certificates does not include the root CA that you need. If that is
  the case, and you still want to trust that chain, you can set
  \code{partial=TRUE} and then \code{PKI.verifyCA} will trust the
  certificates provided in \code{ca} unconditinally, even if they
  don't lead to a trusted root or are not self-signed. Note, however,
  that this is the least secure option and you should only use it if
  the certificates are supplied by you and not the user. If you want
  to support user-supplied intermediate certificates then you can use
  \code{PKI.verifyCA} first to verify the integrity of the
  user-supplied chain with \code{partial=TRUE} and then verify just
  the intermediate certificate against your trusted certificate. That
  way you won't trust the intermediate certificate inadvertently.
}
\value{
  \code{PKI.load.cert}: a certificate object

  \code{PKI.verifyCA}: \code{TRUE} is the certificate can be trusted,
  \code{FALSE} otherwise

  \code{PKI.pubkey}: public key object

  \code{PKI.get.subject}: string containing the subject information in
  one-line RFC2253 format but in UTF8 encoding instead of MBS escapes.
  NOTE: this is experimantal, we may choose to parse the contents and
  return it in native R form as a named vector instead.
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
  (ca <- PKI.load.cert(file=system.file("certs", "RForge-ca.crt", package="PKI")))
  (my.cert <- PKI.load.cert(readLines(system.file("certs", "demo.crt", package="PKI"))))
  PKI.verifyCA(my.cert, ca)
  PKI.pubkey(my.cert)
  PKI.get.subject(my.cert)
  PKI.get.cert.info(my.cert)
}
\keyword{manip}
