\name{PKI.digest}
\alias{PKI.digest}
\title{
  Compute digest sum based on SHA1, SHA256 or MD5 hash functions
}
\description{
  \code{PKI.digest} computes digsest sum based on the hash function
  specified
}
\usage{
PKI.digest(what, hash = c("SHA1", "SHA256", "MD5"))
}
\arguments{
  \item{what}{raw vector of bytes to digest}
  \item{hash}{type of the hash function. Note that "MD5" should
    \emph{not} be used for cryptographic purposes as it is not secure}
}
%\details{
%}
\value{
  Raw vector containg the hash
}
%\references{
%}
\author{
   Simon Urbanek
}
%\note{
%}
\seealso{
  \code{\link{PKI.sign}}
}
\examples{
  PKI.digest(as.raw(1:10))
}
\keyword{manip}
