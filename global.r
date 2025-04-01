# global.R
library(F1DataR)
library(dplyr)
library(ggplot2)
library(caret)
library(randomForest)
library(lubridate)

# Load historical race data
races <- load_races()
pitstops <- load_pitstops()
results <- load_results()
weather <- load_weather()

# Merge datasets
data <- races %>%
  left_join(results, by = "raceId") %>%
  left_join(pitstops, by = c("raceId", "driverId")) %>%
  left_join(weather, by = "raceId")

# Clean and preprocess data
data <- data %>%
  filter(!is.na(lap), !is.na(milliseconds)) %>%
  mutate(
    pitstop_time = milliseconds / 1000,  # Convert to seconds
    weather = as.factor(weather),
    tire_type = as.factor(tire_type)
  )

# Save the cleaned dataset
saveRDS(data, "data/f1_data.rds")