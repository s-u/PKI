# tar one regular file from raw payload
tar1 <- function(name, what, mode=0x180) {
    size <- length(what)
    header <- raw(512L)
    fn <- charToRaw(name)
    header[seq_along(fn)] <- fn
    header[101:107] <- charToRaw(sprintf("%07o", mode))
    header[137:147] <- charToRaw(sprintf("%011o", as.integer(Sys.time())))
    header[157L] <- charToRaw("0") # regular file
    header[125:135] <- charToRaw(sprintf("%011o", as.integer(size)))
    header[149:156] <- charToRaw(" ")
    checksum <- sum(as.integer(header))%%2^24
    header[149:154] <- charToRaw(sprintf("%06o", as.integer(checksum)))
    header[155L] <- as.raw(0L)
    bsize <- ceiling(size / 512L) * 512L
    padding <- raw(bsize - size)
    c(header, what, padding)
}

PKI.sign.tar <- function(tarfile, key, certificate, verify=TRUE, output=tarfile) {
    io <- file
    file <- file(tarfile, "rb")
    on.exit(if (!is.null(file)) close(file))
    magic <- readBin(file, raw(), n = 3)
    if (all(magic[1:2] == c(31, 139)) || all(magic[1:2] == c(31, 157)))
        io <- gzfile
    else if (rawToChar(magic[1:3]) == "BZh") 
        io <- bzfile
    else if (rawToChar(magic[1:5]) == "\xfd7zXZ") 
        io <- xzfile
    close(file)
    file <- NULL
    file <- io(tarfile, "rb")
    chunk <- 4194304L ## 4Mb .. as good as any value ...
    payload <- raw(0)
    while (length(r <- readBin(file, raw(), chunk))) payload <- c(payload, r)
    close(file)
#   FIXME: if we want the .signature to be visible, we need to strip padding to inject new file !
    file <- NULL
    sign <- PKI.sign(payload, key, "SHA1")
    ## SEQ(BIT STREAM sig, subjectPubKeyInfo[if not cert], cert[optional, if present])
    a <- if (missing(certificate)) 
        ASN1.encode(list(ASN1.item(sign, 3L), ASN1.decode(PKI.save.key(key, "DER", FALSE))))
    else
        ASN1.encode(list(ASN1.item(sign, 3L), ASN1.item(raw(0), 0L), ASN1.decode(attr(certificate, "crt.DER"))))
    payload <- c(payload, tar1(".signature", a), as.raw(rep(0L, 1024L)))
    if (inherits(output, "connection")) {
        writeBin(payload, output)
        return(output)
    }
    if (is.raw(output)) return(payload)
    file <- io(as.character(output), "wb")
    writeBin(payload, file)
    close(file)
    file <- NULL
    output
}
