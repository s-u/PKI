## simple test suite - avoid testthat! It has an insane amount of
## unnecessary dependencies. A test package should have exactly 0

assert <- function(msg, what) {
    cat("   . ", msg,"\n")
    stopifnot(what)
    .GlobalEnv$ok <- .GlobalEnv$ok + 1L
}

xfail <- function(...) suppressWarnings(tryCatch({ ...; FALSE }, error=function(e) TRUE))

## none of these are fatal
info <- function(...) message(" -- ", ...)
err  <- function(...) message(" ** ERROR: ", ...)
warn <- function(...) message(" !! ", ...)

## all warnings (unless suppressed) are errors
options(warn=2)

library(PKI)

.GlobalEnv$ok <- 0L

## Majority of tests are in th3 examples,
## so we won't repeat those, but some special cases
## not covered there as well as expected failures

info("Checking failure paths")
xfail(PKI.load.cert(what="foo", file="bar")) ## set both what and file
xfail(PKI.load.cert("foo", "DER")) ## binary format with text
xfail(PKI.load.cert("nothing")) ## invalid content
xfail(PKI.digest("foo", "bar")) ## invalid hash spec
xfail(PKI.load.key(what="foo", file="bar"))
xfail(PKI:::PKI.decode.SSH2(fn.priv.der)) ## try to load invalid content

info("Checking key paths via files/connections")
key <- PKI.genRSAkey(bits = 2048L)
fn.priv.pem <- tempfile()
PKI.save.key(key, target=fn.priv.pem)
fn.priv.der <- tempfile()
PKI.save.key(key, "DER", target=fn.priv.der)
PKI.load.key(file=fn.priv.pem)
PKI.load.key(file=fn.priv.der, format="DER", private=TRUE)
fn.pub.pem <- tempfile()
PKI.save.key(key, target=fn.pub.pem, private=FALSE)
fn.pub.der <- tempfile()
PKI.save.key(key, "DER", target=fn.pub.der, private=FALSE)
PKI.load.key(file=fn.pub.pem)
PKI.load.key(file=fn.pub.der, format="DER", private=FALSE)

info("gmp")
if (requireNamespace("gmp", quietly=TRUE)) {
    PKI.mkRSApubkey(gmp::as.bigz("119445732379544598056145200053932732877863846799652384989588303737527328743970559883211146487286317168142202446955508902936035124709397221178664495721428029984726868375359168203283442617134197706515425366188396513684446494070223079865755643116690165578452542158755074958452695530623055205290232290667934914919"))
} else {
    warn("gmp not found, skipping bignum tests")
}

info("Ciphers")
skey <- PKI.random(256)
for (cipher in c("aes256ecb", "aes256ofb", "bfcbc", "bfecb", "bfofb", "bfcfb"))
    assert(cipher, all(PKI.decrypt(PKI.encrypt(charToRaw("foo!"), skey, cipher), skey, cipher)[1:4] == charToRaw("foo!")))
iv <- PKI.random(256)
for (cipher in c("bfcbc", "bfecb", "bfofb", "bfcfb"))
    assert(paste0(cipher, " (with IV)"),
                  all(PKI.decrypt(PKI.encrypt(charToRaw("foo!"), skey, cipher, iv=iv), skey, cipher, iv=iv)[1:4] == charToRaw("foo!")))

info("ASN.1")

assert("ASN.1 encode/decode", 
{ d <- ASN1.decode(ASN1.encode(ASN1.item(0:255, 3L)))
  ASN1.type(d) == 3L && all(d == as.raw(0:255)) })

info("Tar ball signing")
tmpfn <- c(fn.pub.der, fn.pub.pem, fn.priv.der, fn.priv.pem)
fn <- tempfile()
## on some systems using abs paths can break 100 byte limit
## so we must do this in the tempdir
wd <- getwd()
td <- tempdir()
setwd(td)
tar(fn, basename(tmpfn), "none")
PKI.sign.tar(fn, key)
PKI.verify.tar(fn, key)
setwd(wd)

unlink(c(fn, tmpfn))
