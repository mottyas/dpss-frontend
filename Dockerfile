FROM python:3.12

COPY ./src /app

COPY ./requirements.txt /requirements.txt

RUN pip install -r /requirements.txt --no-cache-dir

EXPOSE 5000

ENTRYPOINT ["python", "/app/main.py"]
