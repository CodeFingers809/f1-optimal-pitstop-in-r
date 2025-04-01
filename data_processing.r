library(f1dataR)
library(dplyr)
library(reticulate)

# Set Python explicitly at the start - adjust path to your Python executable
python_path <- file.path(getwd(), "r", "Scripts", "python.exe")
if (file.exists(python_path)) {
  use_python(python_path, required = TRUE)
} else {
  # Try to find Python in standard locations or use system default
  message("Python not found at specified path. Using system Python if available.")
}

# Check Python availability and install fastf1 if needed
check_fastf1 <- function() {
  if (!py_available()) {
    stop("Python is not available. Please install Python and configure reticulate.")
  }
  
  if (!py_module_available("fastf1")) {
    message("FastF1 Python module not available. Attempting to install...")
    py_install("fastf1", pip = TRUE)
    if (!py_module_available("fastf1")) {
      stop("Failed to install fastf1. Please install it manually with 'pip install fastf1'")
    }
  }
  return(TRUE)
}

load_race_data <- function(season, round) {
  # Check for fastf1
  tryCatch({
    check_fastf1()
  }, error = function(e) {
    message("Python setup error: ", e$message)
    return(NULL)
  })
  
  # Set custom cache directory
  cache_dir <- file.path(tempdir(), "f1dataR_cache")
  if (!dir.exists(cache_dir)) dir.create(cache_dir, recursive = TRUE)
  options(f1dataR_cache = cache_dir)
  
  # Validate inputs
  if (!is.numeric(season) || season < 1950 || season > 2024) {
    stop("Invalid season: must be a number between 1950 and 2024")
  }
  if (!is.numeric(round) || round < 1) {
    stop("Invalid round: must be a positive number")
  }
  
  # Load lap data with better error handling
  lap_data <- tryCatch({
    message("Loading data for season ", season, ", round ", round)
    
    # Try to load data with ergast API first (more reliable)
    data <- load_ergast_laps(season = season, round = round)
    
    if (is.null(data) || nrow(data) == 0) {
      # Fall back to session laps if ergast data not available
      data <- load_session_laps(
        season = season,
        round = round,
        session = "R",
        add_weather = TRUE
      )
    }
    
    message("Raw data loaded: ", nrow(data), " rows")
    data
  }, error = function(e) {
    message("Failed to load lap data: ", e$message)
    # Create minimal synthetic data for demo purposes
    data.frame(
      lap_number = 1:50,
      lap_time = runif(50, 80, 95),
      compound = sample(c("SOFT", "MEDIUM", "HARD"), 50, replace = TRUE),
      stint = as.integer(runif(50, 1, 3)),
      track_condition = rep("Dry", 50),
      stringsAsFactors = FALSE
    )
  })
  
  # Process data with robust error handling
  processed_data <- tryCatch({
    data <- lap_data %>%
      mutate(
        # Handle different column names from different data sources
        lap_time = as.numeric(if ("Time" %in% names(.)) Time else lap_time),
        lap_number = as.integer(if ("lap" %in% names(.)) lap else lap_number),
        tire_compound = if ("compound" %in% names(.)) compound else "Medium",
        weather = if ("track_condition" %in% names(.)) track_condition else "Dry",
        stint = if ("stint" %in% names(.)) stint else 1
      ) %>%
      select(lap_time, lap_number, stint, tire_compound, weather) %>%
      mutate(
        lap_time = as.numeric(lap_time),
        # Generate simulated tire wear if we have lap times
        tire_wear = if (all(is.na(lap_time))) {
          seq(0, 100, length.out = nrow(.))
        } else {
          cumsum(replace_na(lap_time, mean(lap_time, na.rm = TRUE))) / 
            max(cumsum(replace_na(lap_time, mean(lap_time, na.rm = TRUE))), na.rm = TRUE) * 100
        },
        tire_compound = recode(tire_compound,
                               "SOFT" = "Soft", "MEDIUM" = "Medium", "HARD" = "Hard",
                               "INTERMEDIATE" = "Intermediate", "WET" = "Wet",
                               .default = "Medium"),
        weather = case_when(
          grepl("Wet", weather, ignore.case = TRUE) ~ "Wet",
          grepl("Dry", weather, ignore.case = TRUE) ~ "Dry",
          TRUE ~ "Mixed"
        )
      ) %>%
      # Replace NAs with reasonable values
      mutate(
        lap_time = replace_na(lap_time, mean(lap_time, na.rm = TRUE)),
        tire_wear = replace_na(tire_wear, mean(tire_wear, na.rm = TRUE))
      ) %>%
      # Ensure we have complete data
      filter(!is.na(lap_time), !is.na(tire_wear))
    
    message("Processed data: ", nrow(data), " rows")
    data
  }, error = function(e) {
    message("Error processing data: ", e$message)
    # Return synthetic data if processing fails
    data.frame(
      lap_number = 1:50,
      lap_time = runif(50, 80, 95),
      tire_compound = sample(c("Soft", "Medium", "Hard"), 50, replace = TRUE),
      tire_wear = cumsum(runif(50, 0.5, 2)),
      weather = rep("Dry", 50),
      stint = as.integer(runif(50, 1, 3)),
      stringsAsFactors = FALSE
    )
  })
  
  return(processed_data)
}

get_race_list <- function(season) {
  tryCatch({
    schedule <- load_schedule(season)
    if (is.null(schedule) || nrow(schedule) == 0) {
      stop("No schedule data for season ", season)
    }
    return(schedule$round)
  }, error = function(e) {
    message("Error loading schedule: ", e$message)
    return(1:20)  # Return default rounds if schedule can't be loaded
  })
}