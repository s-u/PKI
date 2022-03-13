\name{PKI.info}
\alias{PKI.info}
\title{
Retrieve PKI back-end information
}
\description{
  \code{PKI.info} returns information about the engine which is
  providing the PKI functionality.
}
\usage{
PKI.info()
}
\value{
Named list:
\item{engine}{string, name of the engine, currently either
  \code{"openssl"} or \code{"libressl"}}
\item{version}{numeric, version of the engine as a real number in the
  form \code{major.minor}}
\item{description}{string, description of the engine, its version and
  any futher information that the engine may provide}
}
\author{
Simon Urbanek
}
\note{
  This function should be treated as informational only. The return
  value is subject to change, mainly we may extend it to possibly supply
  information on available ciphers etc.

  Older versions of OpenSSL did not provide functional API to retrieve
  version inforation, so versions < 1.1 may not reflect the true version,
  but rather the values from the headers at compile time which may not
  be the same as the loaded library at run-time.
}
\examples{
str(PKI.info())
}
\keyword{interface}
