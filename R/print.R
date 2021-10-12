print.X509cert <- function(x, short=FALSE, ...) {
  if (short) {
    cat("X509 Cert: ", PKI.get.subject(x), "\n")
  } else {
    i <- PKI.get.cert.info(x)
    cat(
"X509 Certificate:\n  Subject: ", i[[1]],
"\n  Issuer: ", i[[2]],
"\n  Fingerprint (SHA-1): ", raw2hex(i[[3]], ':'),
"\n  Validity: ", paste(.POSIXct(i[[4]]), collapse=" ... "),
if (i[[5]]) " (is CA)" else "",
"\n\n", sep='')
  }
  invisible(x)
}
