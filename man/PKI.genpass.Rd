\name{PKI.genpass}
\alias{PKI.genpass}
\title{
  Generate cryptographically strong pseudo-random password.
}
\description{
  \code{PKI.genpass} generates \code{n} cryptographically strong
  pseudo-random password by using a given set of allowed characters.
}
\usage{
PKI.genpass(n=15, set=c(alphanum, ".", "/"), block=5, sep="-")
}
\arguments{
  \item{n}{positive integer, number of random elements in the password}
  \item{set}{character vector, set of characters to use in the
    password, ideally its length should be a power of 2 and must be at
    most 256. Internal variable \code{alphanum} is equivalent to
    \code{c(LETTERS, letters, 0:9)}.}
  \item{block}{non-negative integer, number of character blocks in the
    password or 0 if no separated blocks are desired.}
  \item{sep}{string, separator between blocks (only used if 0 <
    \code{blocks} < \code{n}).}
}
\details{
  \code{PKI.genpass} generates a password based on a set of allowable
  characters by subsetting the set with bytes generated using
  \code{\link{PKI.random}}.

  If \code{block} is >0 and <\code{n} then blocks of \code{block}
  characters are separated by the separator string \code{sep}. This is
  typically used to guarantee at least one special character in the
  password. The default results in a 90-bit random password of the form
  \code{XXXXX-XXXXX-XXXXX}.
}
\value{
  String, generated password.
}
\author{
   Simon Urbanek
}
\note{
  This is just a utility front-end to \code{\link{PKI.random}(n)} to
  subset \code{set} modulo its length. If the set does not have a length
  which is a power of 2 then a warning is issued and the leading
  elements are more likely to be used, reducing the password strength.
}
\examples{
  PKI.genpass()
}
\keyword{manip}
