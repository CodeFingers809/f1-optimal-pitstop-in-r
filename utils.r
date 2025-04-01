# Utility functions for F1 Pitstop Predictor

# Function to check and install required packages
check_packages <- function() {
  required_packages <- c("shiny", "f1dataR", "ggplot2", "dplyr", "randomForest", "reticulate")
  
  # Check if packages are installed
  missing_packages <- required_packages[!sapply(required_packages, requireNamespace, quietly = TRUE)]
  
  # Install missing packages
  if (length(missing_packages) > 0) {
    message("Installing missing packages: ", paste(missing_packages, collapse = ", "))
    install.packages(missing_packages)
  }
  
  # Load all required packages
  for (pkg in required_packages) {
    library(pkg, character.only = TRUE)
  }
  
  return(TRUE)
}

# Function to print debug info
debug_info <- function(msg, data = NULL) {
  message(Sys.time(), " - ", msg)
  if (!is.null(data) && is.data.frame(data)) {
    message("  Rows: ", nrow(data))
    message("  Columns: ", paste(names(data), collapse = ", "))
  }
}

# Function to get tire color for plots
get_tire_color <- function(compound) {
  switch(compound,
         "Soft" = "#FF3333",
         "Medium" = "#FFCC33",
         "Hard" = "#FFFFFF",
         "Intermediate" = "#33CC33",
         "Wet" = "#3333FF",
         "#999999")  # Default gray
}

# Function to estimate pit stop time for a circuit
estimate_pitstop_time <- function(circuit_name) {
  # Average pit stop times in seconds for different circuits
  # These are approximate values
  pit_times <- list(
    "Albert Park" = 23,
    "Bahrain" = 21,
    "Jeddah" = 22,
    "Imola" = 23,
    "Miami" = 24,
    "Barcelona" = 21,
    "Monaco" = 25,
    "Montreal" = 22,
    "Silverstone" = 20,
    "Red Bull Ring" = 19,
    "Paul Ricard" = 21,
    "Hungaroring" = 22,
    "Spa" = 20,
    "Zandvoort" = 23,
    "Monza" = 19,
    "Baku" = 22,
    "Marina Bay" = 24,
    "Suzuka" = 21,
    "COTA" = 22,
    "Mexico" = 23,
    "Interlagos" = 21,
    "Las Vegas" = 23,
    "Losail" = 22,
    "Yas Marina" = 21
  )
  
  # Return the pit stop time for the given circuit, or an average value if not found
  return(pit_times[[circuit_name]] %||% 22)
}

# Safe conversion functions that handle errors gracefully
safe_as_numeric <- function(x) {
  result <- suppressWarnings(as.numeric(x))
  ifelse(is.na(result), 0, result)
}

safe_as_integer <- function(x) {
  result <- suppressWarnings(as.integer(x))
  ifelse(is.na(result), 0, result)
}

# Function to safely extract data from inconsistent API responses
safe_extract <- function(data, column, default = NA) {
  if (is.null(data) || !is.data.frame(data)) {
    return(default)
  }
  
  if (column %in% names(data)) {
    return(data[[column]])
  } else {
    return(rep(default, nrow(data)))
  }
}

# Null coalescing operator
`%||%` <- function(a, b) {
  if (is.null(a)) b else a
}