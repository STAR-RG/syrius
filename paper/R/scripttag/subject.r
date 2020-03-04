#!/usr/bin/env Rscript

pdf("scripttag.pdf", width = 4.1, height = 2.9)

df1 <- read.table("data1.txt", header = FALSE)
df2 <- read.table("data5.txt", header = FALSE)
df3 <- read.table("data10.txt", header = FALSE)
df4 <- read.table("data23.txt", header = FALSE)

# adjusting margins
par(mar = c(5, 4, 4, 0), 
    mgp = c(1, 1, 0),
    mai = c(0.4, 0.6, 0.1, 0),
    mfrow = c(1,2))

bp <- boxplot(df1$V1,df2$V1,df3$V1,df4$V1,names=c("1","5","10","23"), boxwex=0.2, cex.axis=1, las=1)

dev.off()

