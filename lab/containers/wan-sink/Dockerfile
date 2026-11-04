FROM python:3.11-slim
RUN pip install flask
RUN mkdir -p /data
WORKDIR /app
COPY app.py /app/app.py
VOLUME ["/data"]
CMD ["python3", "app.py"]
