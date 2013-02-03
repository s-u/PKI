\name{raw2hex}
\alias{raw2hex}
\title{
  Convert raw vector to string hex representation
}
\description{
  \code{raw2hex} convers a raw vector into hexadecimal representation
}
\usage{
raw2hex(what, sep, upper = FALSE)
}
\arguments{
  \item{what}{raw vector}
  \item{sep}{optional separator string}
  \item{upper}{logical, if \code{TRUE} then upper case letters are used,
    otherwise any letters will be lower case.}
}
\details{
  If \code{sep} is omitted or \code{NULL} then the resulting character
  vector will have as many elements as the raw vector. Otherwise the
  elements are concatenated using the specified separator into one
  character string. This is much more efficient than using
  \code{paste(raw2hex(x), collapse=sep)}, but has the same effect.
}
\value{
  Character vector with the hexadecimal representation of the raw vector.
}
%\references{
%}
\author{
  Simon Urbanek
}
%\note{
%}
\examples{
raw2hex(PKI.digest(raw(), "SHA1"), "")
raw2hex(PKI.digest(raw(), "MD5"), ":")

## this is jsut a performance comparison and a test that
## raw2hex can handle long strings
x <- as.raw(runif(1e5) * 255.9)
system.time(h1 <- raw2hex(x, " "))
system.time(h2 <- paste(raw2hex(x), collapse=" "))
stopifnot(identical(h1, h2))
}
\keyword{manip}
