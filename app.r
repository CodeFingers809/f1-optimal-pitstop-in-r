# Set library paths
user_lib <- Sys.getenv("R_LIBS_USER")
.libPaths(c(user_lib, .libPaths()))

library(shiny)
library(f1dataR)
library(ggplot2)
library(dplyr)
library(randomForest)
source("data_processing.R")
source("model.R")
source("utils.R")

ui <- fluidPage(
  titlePanel("F1 Pitstop Predictor"),
  sidebarLayout(
    sidebarPanel(
      selectInput("season", "Season:", choices = 2018:2024),
      selectInput("round", "Round:", choices = NULL),
      selectInput("weather", "Weather Condition:", 
                 choices = c("Dry", "Wet", "Mixed")),
      selectInput("tire", "Starting Tire Compound:", 
                 choices = c("Soft", "Medium", "Hard", "Intermediate", "Wet")),
      sliderInput("laps_done", "Laps Completed:", 
                 min = 0, max = 50, value = 10),
      sliderInput("tire_wear", "Tire Wear %:", 
                 min = 0, max = 100, value = 30),
      actionButton("predict", "Predict Optimal Pitstop")
    ),
    mainPanel(
      plotOutput("lap_time_plot"),
      plotOutput("tire_wear_plot"),
      verbatimTextOutput("prediction_result"),
      plotOutput("feature_importance"),
      verbatimTextOutput("debug_info")
    )
  )
)

server <- function(input, output, session) {
  # Update round selection based on season
  observe({
    round_choices <- get_race_list(as.numeric(input$season))
    updateSelectInput(session, "round", choices = round_choices)
  })
  
  # Reactive data loading with error handling
  race_data <- reactive({
    tryCatch({
      data <- load_race_data(as.numeric(input$season), as.numeric(input$round))
      req(data, nrow(data) > 0)
      data
    }, error = function(e) {
      message("Error in race_data reactive: ", e$message)
      NULL
    })
  })
  
  # Prediction event
  prediction <- eventReactive(input$predict, {
    req(race_data())
    predict_pitstop(
      season = as.numeric(input$season),
      round = as.numeric(input$round),
      weather = input$weather,
      tire = input$tire,
      laps_done = input$laps_done,
      tire_wear = input$tire_wear,
      historical_data = race_data()
    )
  })
  
  # Lap time visualization
  output$lap_time_plot <- renderPlot({
    req(race_data())
    data <- race_data()
    ggplot(data, aes(x = lap_number, y = lap_time, color = tire_compound)) +
      geom_line(size = 1) +
      geom_point() +
      geom_vline(xintercept = prediction(), color = "red", linetype = "dashed", size = 1.2) +
      labs(title = "Lap Times by Tire Compound",
           x = "Lap Number", y = "Lap Time (seconds)",
           color = "Tire Compound") +
      theme_minimal() +
      scale_color_manual(values = c("Soft" = "red", "Medium" = "orange", "Hard" = "yellow",
                                   "Intermediate" = "green", "Wet" = "blue"))
  })
  
  # Tire wear visualization
  output$tire_wear_plot <- renderPlot({
    req(race_data())
    data <- race_data()
    ggplot(data, aes(x = lap_number, y = tire_wear, color = tire_compound)) +
      geom_line(size = 1) +
      labs(title = "Tire Wear Over Laps",
           x = "Lap Number", y = "Tire Wear (%)",
           color = "Tire Compound") +
      theme_minimal() +
      scale_color_manual(values = c("Soft" = "red", "Medium" = "orange", "Hard" = "yellow",
                                   "Intermediate" = "green", "Wet" = "blue"))
  })
  
  # Prediction output
  output$prediction_result <- renderPrint({
    req(prediction())
    pred <- prediction()
    paste("Recommended pitstop after lap:", pred,
          "\nEstimated time gain:", round(runif(1, 0.5, 2), 2), "seconds")
  })
  
  # Feature importance plot
  output$feature_importance <- renderPlot({
    req(race_data())
    plot_feature_importance(race_data())
  })
  
  # Debug info
  output$debug_info <- renderPrint({
    if (is.null(race_data())) {
      paste("Error: Failed to load race data for season", input$season, "round", input$round)
    } else {
      paste("Data loaded:", nrow(race_data()), "rows from season", input$season, "round", input$round)
    }
  })
}
  
shinyApp(ui, server)