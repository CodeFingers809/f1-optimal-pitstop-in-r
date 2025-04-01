library(randomForest)
library(dplyr)

# Function to predict optimal pitstop
predict_pitstop <- function(season, round, weather, tire, laps_done, tire_wear, historical_data = NULL) {
  # If no historical data, return a reasonable default
  if (is.null(historical_data) || nrow(historical_data) == 0) {
    message("No historical data available, using simulated prediction")
    # Return a reasonable pitstop lap based on tire compound and laps done
    base_lap <- switch(tire,
                       "Soft" = 15,
                       "Medium" = 25,
                       "Hard" = 35,
                       "Intermediate" = 20,
                       "Wet" = 18,
                       20)  # Default
    
    # Adjust for weather
    weather_factor <- switch(weather,
                             "Dry" = 1.0,
                             "Wet" = 0.8,
                             "Mixed" = 0.9,
                             1.0)  # Default
    
    # Adjust for tire wear (higher wear = earlier stop)
    wear_factor <- 1 - (tire_wear / 100) * 0.5
    
    return(max(laps_done + 1, round(base_lap * weather_factor * wear_factor)))
  }
  
  # Prepare model data
  model_data <- historical_data %>%
    group_by(stint) %>%
    mutate(
      lap_delta = c(0, diff(lap_time)),
      performance_drop = cumsum(pmax(0, lap_delta))
    ) %>%
    ungroup() %>%
    # Add additional features
    mutate(
      # Convert factors to numeric for model
      weather_num = as.numeric(factor(weather)),
      compound_num = as.numeric(factor(tire_compound)),
      # Add interaction terms
      wear_performance = tire_wear * performance_drop
    )
  
  # Threshold for when a pitstop is optimal
  # (when performance drop exceeds a threshold relative to tire life)
  optimal_pitstop <- model_data %>%
    group_by(stint) %>%
    mutate(
      # Create target variable for when a pit should occur
      # (when performance drops significantly or wear is high)
      should_pit = performance_drop > median(performance_drop, na.rm = TRUE) * 1.5 |
        tire_wear > 75
    ) %>%
    filter(should_pit) %>%
    summarize(optimal_lap = min(lap_number, na.rm = TRUE)) %>%
    pull(optimal_lap)
  
  if (length(optimal_pitstop) == 0 || all(is.na(optimal_pitstop))) {
    # If no clear optimal point, use a heuristic
    optimal_pitstop <- switch(tire,
                              "Soft" = 15,
                              "Medium" = 25,
                              "Hard" = 35,
                              "Intermediate" = 20,
                              "Wet" = 18,
                              20)  # Default
  }
  
  # Don't recommend pitting before current lap
  return(max(laps_done + 1, min(optimal_pitstop, na.rm = TRUE)))
}

# Function to plot feature importance
plot_feature_importance <- function(race_data) {
  if (is.null(race_data) || nrow(race_data) < 10) {
    # Return an empty plot with message if no data
    plot(0, 0, type = "n", axes = FALSE, xlab = "", ylab = "")
    text(0, 0, "Insufficient data for feature importance")
    return()
  }
  
  # Prepare data for model
  model_data <- race_data %>%
    mutate(
      weather_num = as.numeric(factor(weather)),
      compound_num = as.numeric(factor(tire_compound))
    ) %>%
    # Create synthetic target for demo purposes
    mutate(
      performance = lap_time + tire_wear * 0.1,
      target = performance > median(performance, na.rm = TRUE)
    )
  
  # Select features
  features <- c("lap_number", "tire_wear", "weather_num", "compound_num")
  
  # Ensure we have complete data
  model_data <- model_data %>%
    select(all_of(c(features, "target"))) %>%
    filter(complete.cases(.))
  
  # Check if we have enough data
  if (nrow(model_data) < 10) {
    plot(0, 0, type = "n", axes = FALSE, xlab = "", ylab = "")
    text(0, 0, "Insufficient complete data for model")
    return()
  }
  
  # Build random forest model
  tryCatch({
    model <- randomForest(
      x = model_data[, features],
      y = as.factor(model_data$target),
      ntree = 50,
      importance = TRUE
    )
    
    # Extract feature importance
    importance <- importance(model)
    
    # Plot feature importance
    feature_names <- c("Lap Number", "Tire Wear", "Weather", "Compound")
    par(mar = c(5, 10, 4, 2))
    barplot(
      importance[, "MeanDecreaseGini"],
      names.arg = feature_names,
      horiz = TRUE,
      las = 1,
      col = "steelblue",
      main = "Feature Importance for Pitstop Prediction",
      xlab = "Importance (Mean Decrease Gini)"
    )
  }, error = function(e) {
    # Plot error message if model fails
    plot(0, 0, type = "n", axes = FALSE, xlab = "", ylab = "")
    text(0, 0, paste("Model error:", e$message))
  })
}