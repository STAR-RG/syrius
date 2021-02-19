#!/usr/bin/env Rscript

pdf("jsp.pdf", width = 6.5, height = 3)


df1 <- read.table("data0.txt", header = FALSE)
df2 <- read.table("data1.txt", header = FALSE)
df3 <- read.table("data100.txt", header = FALSE)
df4 <- read.table("data10000.txt", header = FALSE)
df5 <- read.table("data100000.txt", header = FALSE)

# adjusting margins
par(mar = c(5, 4, 4, 0), 
    mgp = c(1, 1, 0),
    mai = c(0.4, 0.6, 0.1, 0),
    mfrow = c(1,2))

bp <- boxplot(df1$V1,df2$V1,df3$V1,df4$V1,df5$V1,names=c("0","1","100","10k","100k"), boxwex=0.2, cex.axis=1, las=1)

dev.off()

