# Use the official R Shiny image
FROM rocker/shiny:4.1.0

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    python3 \
    python3-pip

# Install R packages from requirements.r
COPY requirements.r /requirements.r
RUN R -e "source('/requirements.r')"

# Install Python packages from requirements.txt
COPY requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

# Copy the app files to the Shiny server directory
COPY . /srv/shiny-server/

# Set permissions for the Shiny server
RUN chown -R shiny:shiny /srv/shiny-server

# Expose port 3838 for Shiny app
EXPOSE 3838

# Run the Shiny app
CMD ["R", "-e", "shiny::runApp('/srv/shiny-server/app.r', port=3838, host='0.0.0.0')"]