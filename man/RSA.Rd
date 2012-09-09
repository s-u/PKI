\name{RSA}
\alias{RSA}
\alias{PKI.genRSAkey}
\alias{PKI.load.privkey}
\title{
  PKI functions handling RSA keys 
}
\description{
  \code{PKI.load.privkey} loads an RSA private key in PKCS#1 PEM format.

  \code{PKI.genRSAkey} generates RSA public/private key pair.
}
\usage{
PKI.load.privkey(what, file)
PKI.genRSAkey(bits = 2048L)
}
\arguments{
  \item{what}{string, raw vector or connection to load the key from}
  \item{file}{filename to load the key from - \code{what} and
    \code{file} are mutually exclusive}
  \item{bits}{size of the generated key in bits. Must be \code{2 ^ n}
    with integer \code{n > 8}.}
}
%\details{
%}
\value{
  \code{PKI.load.privkey}: private key object
  
  \code{PKI.genRSAkey}: private + public key object 
}
%\references{
%}
\author{
  Simon Urbanek
}
%\note{
%}
\seealso{\code{\link{PKI.encrypt}}, \code{\link{PKI.decrypt}}, \code{\link{PKI.pubkey}}}
%\examples{
%}
\keyword{manip}
