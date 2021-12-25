FROM python:3.9-alpine

# Set the working directory to /app
WORKDIR /app

# Set this to fix a bug in c include files not being found
ENV LIBRARY_PATH=/lib:/usr/lib

ADD requirements.txt /app

RUN pip3 install -r requirements.txt

ADD api-browser.py /app
RUN mkdir /app/static
RUN mkdir /app/static/images
RUN mkdir /app/static/stylesheets
RUN mkdir /app/templates
ADD static/images/* /app/static/images/
ADD static/stylesheets/* /app/static/stylesheets/
ADD templates/* /app/templates/

# Run app.py when the container launches
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 api-browser:app

