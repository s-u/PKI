\name{BIGNUMint}
\alias{BIGNUMint}
\alias{as.BIGNUMint}
\title{
  Functions for BIGNUM representation of arbitrarily precise integers
}
\description{
  \code{as.BIGNUMint} encodes integer in BIGNUM format as raw vector as
  used by ASN.1 format.
}
\usage{
as.BIGNUMint(what, scalar = TRUE)
}
\arguments{
  \item{what}{representation of an integer or a vector
    thereof. Currently supported formats include \code{"bigz"} objects
    from the \code{"gmp"} package, integers and reals.
  }
  \item{scalar}{if \code{TRUE} then the input is expected to be scalar
    and only the first element will be used (zero-length vectors raise
    an error). Otherwise the result will be a list of all converted
    elements.
  }
}
\details{
  The BIGNUM representation as used in ASN.1 is a big-endian encoding of
  variable length stored in a raw vector. Negative numbers are stored in
  two-complement's encoding, but are currently unsupported by
  \code{as.BIGNUMint}.
}
\value{
  Raw vector in BIGNUM integer representation.
}
%\references{
%}
\author{
  Simon Urbanek
}
\note{
  Unless the input is of class \code{"bigz"} then 32-bit platforms only
  support integers up to 32-bit, 64-bit platforms up to 53-bit (when
  real vectors are used).
}
%\seealso{
%}
\examples{
as.BIGNUMint(65537)
}
\keyword{manip}
