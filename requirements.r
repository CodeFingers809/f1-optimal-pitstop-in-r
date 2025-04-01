# Create personal library directory if it doesn't exist
user_lib <- Sys.getenv("R_LIBS_USER")
if (!dir.exists(user_lib)) dir.create(user_lib, recursive = TRUE)

# Set CRAN mirror (e.g., a popular one like "https://cloud.r-project.org")
options(repos = "https://cloud.r-project.org")

# Install required packages to user library
if (!require("shiny")) install.packages("shiny", lib = user_lib)
if (!require("f1dataR")) remotes::install_github("SCasanova/f1dataR", lib = user_lib)
if (!require("ggplot2")) install.packages("ggplot2", lib = user_lib)
if (!require("dplyr")) install.packages("dplyr", lib = user_lib)
if (!require("randomForest")) install.packages("randomForest", lib = user_lib)
if (!require("remotes")) install.packages("remotes", lib = user_lib)
if (!require("jsonlite")) install.packages("jsonlite", lib = user_lib)  # Added for VS Code compatibility

# Add user library to search path
.libPaths(c(user_lib, .libPaths()))

