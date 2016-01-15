\name{PKI.random}
\alias{PKI.random}
\title{
  Generate cryptographically strong pseudo-random bytes.
}
\description{
  \code{PKI.random} generates \code{n} cryptographically strong
  pseudo-random bytes.
}
\usage{
PKI.random(n)
}
\arguments{
  \item{n}{non-negative integer, number of bytes to generate}
}
\details{
  \code{PKI.random} is the preferred way to generate cryptographically
  strong random content that can be used as keys, seeds etc. Not to be
  confused with random number generators in R, it is entirely separate
  for cryptographics purposes.
}
\value{
  Raw vector of \code{n} cryptographically strong pseudo-random bytes.
}
%\references{
%}
\author{
   Simon Urbanek
}
%\note{
%}
\examples{
  PKI.random(10)
}
\keyword{manip}
