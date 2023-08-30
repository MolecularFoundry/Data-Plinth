# Dockerfile
FROM python:3
WORKDIR /srv
COPY . /srv
RUN pip install --upgrade pip
RUN pip install -r requirements.txt --upgrade 

ENV FLASK_APP=app
CMD ["python","oidc_server.py"]
#CMD ["python","server.py"]