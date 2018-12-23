FROM python:3.6-alpine

# Set the working directory to /app
WORKDIR /app
ADD requirements.txt /app

RUN pip install -r requirements.txt

ADD main.py /app
RUN mkdir /app/static
RUN mkdir /app/static/images
RUN mkdir /app/static/stylesheets
RUN mkdir /app/templates
ADD static/images/* /app/static/images/
ADD static/stylesheets/* /app/static/stylesheets/
ADD templates/* /app/templates/

RUN ls -R

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launches
CMD ["python3", "main.py"]
