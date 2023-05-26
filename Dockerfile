# Dockerfile
FROM python:3.9.10-alpine3.14
WORKDIR /srv
COPY . /srv
RUN pip install --upgrade pip
RUN pip install -r requirements.txt --upgrade 

ENV FLASK_APP=app
CMD ["python","oidc_server.py"]
#CMD ["python","server.py"]