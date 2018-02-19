# basic packages for plotting, data generation, latex output, reading excel files, doing HTTP requeists, etc
Needed <- c("car", "rgl", "Hmisc", "scatterplot3d", "ggplot2", "lattice", "mvtnorm", "tikzDevice", "readxl", "httr", "readr")
install.packages(Needed, repos = "http://cran.us.r-project.org")

# Packages for clustering, text data mining
Needed <- c("tm", "SnowballCC", "RColorBrewer", "wordcloud", "biclust", "cluster", "igraph", "fpc")
install.packages(Needed, dependencies = TRUE, repos = "http://cran.us.r-project.org")

# something
Needed <- c("Rcampdf")
install.packages(Needed, repos = "http://datacube.wu.ac.at/", type = "source")
