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
    header
    bsize <- ceiling(size / 512L) * 512L
    padding <- raw(bsize - size)
    c(header, what, padding)
}

PKI.sign.tar <- function(tarfile, key, certificate, verify=TRUE) {
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
    
}